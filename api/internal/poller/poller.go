package poller

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/NorskHelsenett/spam/internal/assets"
	"github.com/NorskHelsenett/spam/internal/jobs"
	"github.com/NorskHelsenett/spam/internal/providerconfig"
	"github.com/NorskHelsenett/spam/internal/providers"
	"github.com/NorskHelsenett/spam/internal/runner"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// Poller checks providers with configured poll intervals for new commits.
type Poller struct {
	db    *gorm.DB
	store *providerconfig.Store
	mu    sync.Mutex
	last  map[string]time.Time // providerID -> last poll time
}

// New creates a new Poller.
func New(db *gorm.DB, store *providerconfig.Store) *Poller {
	return &Poller{
		db:    db,
		store: store,
		last:  make(map[string]time.Time),
	}
}

// Poll checks all providers with polling enabled and queues scans for new commits.
// Called every worker tick (~2s); the poller handles per-provider interval checks internally.
func (p *Poller) Poll(ctx context.Context) {
	providerList, err := p.store.ListEnabledWithPolling(ctx)
	if err != nil {
		log.Printf("poller: list providers: %v", err)
		return
	}

	for _, provider := range providerList {
		if provider.PollInterval == nil || *provider.PollInterval <= 0 {
			continue
		}

		interval := time.Duration(*provider.PollInterval) * time.Second

		p.mu.Lock()
		lastPoll := p.last[provider.ID]
		p.mu.Unlock()

		if time.Since(lastPoll) < interval {
			continue
		}

		p.pollProvider(ctx, provider)

		p.mu.Lock()
		p.last[provider.ID] = time.Now()
		p.mu.Unlock()
	}
}

func (p *Poller) pollProvider(ctx context.Context, provider providerconfig.ProviderInstance) {
	token, err := p.store.GetActiveToken(ctx, provider.ID)
	if err != nil {
		log.Printf("poller: get token for %s: %v", provider.DisplayName, err)
		return
	}

	client := createClient(provider.Type, provider.BaseURL, token)
	if client == nil {
		log.Printf("poller: unknown provider type %s for %s", provider.Type, provider.DisplayName)
		return
	}

	// Fetch all repos (paginated)
	var allRepos []providers.RepoData
	page := 1
	for {
		repos, pageInfo, err := client.ListPublicRepos(ctx, provider.OwnerPath, providers.ListOptions{
			Page:     page,
			PageSize: 100,
		})
		if err != nil {
			log.Printf("poller: list repos for %s page %d: %v", provider.DisplayName, page, err)
			break
		}
		allRepos = append(allRepos, repos...)
		if !pageInfo.HasNextPage {
			break
		}
		page++
	}

	if len(allRepos) == 0 {
		return
	}

	var queued, skippedSame, skippedPending int
	for _, repo := range allRepos {
		if repo.DefaultBranch == "" {
			continue
		}
		if repo.IsDisabled {
			continue
		}

		latestSHA, err := client.GetLatestCommit(ctx, repo.FullPath, repo.DefaultBranch)
		if err != nil {
			// Skip repos where we can't get the latest commit (empty repos, permission issues, etc.)
			continue
		}

		// Upsert repo record
		org := ""
		slug := repo.FullPath
		if parts := strings.Split(repo.FullPath, "/"); len(parts) > 1 {
			org = parts[0]
			slug = parts[len(parts)-1]
		}

		repoRecord, err := assets.UpsertRepo(ctx, p.db, assets.RepoInput{
			Provider: provider.Type,
			Org:      org,
			Slug:     slug,
		})
		if err != nil {
			log.Printf("poller: upsert repo %s: %v", repo.FullPath, err)
			continue
		}

		// Check last scanned commit from completed runs
		lastScannedSHA := p.getLastScannedCommit(ctx, repoRecord.ID)
		if lastScannedSHA == latestSHA {
			skippedSame++
			continue
		}

		// Check if there's already a pending job for this repo
		if p.hasPendingJob(ctx, repoRecord.ID) {
			skippedPending++
			continue
		}

		// Queue new scan with pinned commit SHA
		cloneURL := buildCloneURL(provider.Type, repo.FullPath, provider.BaseURL)
		if cloneURL == "" {
			continue
		}

		payload := jobs.CreateRunPayload{
			RepoID:       repoRecord.ID,
			ProviderID:   provider.ID,
			Provider:     provider.Type,
			CloneURL:     cloneURL,
			Ref:          repo.DefaultBranch,
			CommitSHA:    latestSHA,
			RepoDisabled: repo.IsDisabled,
		}

		payloadBytes, err := json.Marshal(payload)
		if err != nil {
			log.Printf("poller: marshal payload for %s: %v", repo.FullPath, err)
			continue
		}

		now := time.Now()
		job := map[string]any{
			"id":           uuid.New().String(),
			"type":         jobs.JobTypeCreateRun,
			"status":       "QUEUED",
			"payload":      payloadBytes,
			"attempts":     0,
			"max_attempts": 3,
			"run_at":       now,
			"created_at":   now,
			"updated_at":   now,
		}

		if err := p.db.WithContext(ctx).Table("jobs").Create(job).Error; err != nil {
			log.Printf("poller: create job for %s: %v", repo.FullPath, err)
			continue
		}

		queued++
	}

	if queued > 0 || skippedPending > 0 {
		log.Printf("poller: %s — queued=%d skipped_same=%d skipped_pending=%d total=%d",
			provider.DisplayName, queued, skippedSame, skippedPending, len(allRepos))
	}
}

// getLastScannedCommit returns the commit_hash of the last SUCCEEDED run for a repo.
func (p *Poller) getLastScannedCommit(ctx context.Context, repoID string) string {
	var run runner.Run
	err := p.db.WithContext(ctx).
		Where("type = ? AND status = ?", jobs.JobTypeCreateRun, "SUCCEEDED").
		Where("payload->>'repo_id' = ?", repoID).
		Order("finished_at DESC").
		First(&run).Error
	if err != nil {
		return ""
	}
	return run.CommitHash
}

// hasPendingJob checks if there's already a QUEUED or RUNNING job for this repo.
func (p *Poller) hasPendingJob(ctx context.Context, repoID string) bool {
	var count int64
	p.db.WithContext(ctx).Table("jobs").
		Where("type = ?", jobs.JobTypeCreateRun).
		Where("status IN ?", []string{"QUEUED", "RUNNING"}).
		Where("payload->>'repo_id' = ?", repoID).
		Count(&count)
	return count > 0
}

func createClient(providerType, baseURL, token string) providers.Client {
	switch providerType {
	case "github":
		return providers.NewGitHubClient(baseURL, token)
	case "gitlab":
		return providers.NewGitLabClient(baseURL, token)
	case "gitea", "forgejo":
		return providers.NewGiteaClient(baseURL, token)
	default:
		return nil
	}
}

func buildCloneURL(provider, repoPath, baseURL string) string {
	switch provider {
	case "github":
		return "https://github.com/" + repoPath + ".git"
	case "gitlab":
		if baseURL != "" {
			return fmt.Sprintf("%s/%s.git", strings.TrimRight(baseURL, "/"), repoPath)
		}
		return "https://gitlab.com/" + repoPath + ".git"
	case "gitea", "forgejo":
		if baseURL == "" {
			return ""
		}
		return fmt.Sprintf("%s/%s.git", strings.TrimRight(baseURL, "/"), repoPath)
	default:
		return ""
	}
}
