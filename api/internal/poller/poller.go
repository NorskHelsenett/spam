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
	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// Poller checks providers with configured poll intervals for new commits.
type Poller struct {
	db    *gorm.DB
	store *providerconfig.Store
	mu    sync.Mutex
	last  map[string]time.Time // providerID -> last poll time
}

type SyncResult struct {
	ProviderID     string `json:"provider_id"`
	ProviderName   string `json:"provider_name"`
	HealthStatus   string `json:"health_status"`
	HealthMessage  string `json:"health_message,omitempty"`
	TotalRepos     int    `json:"total_repos"`
	Queued         int    `json:"queued"`
	SkippedSame    int    `json:"skipped_same"`
	SkippedPending int    `json:"skipped_pending"`
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

		if _, err := p.syncProvider(ctx, provider); err != nil {
			log.Printf("poller: sync provider %s: %v", provider.DisplayName, err)
		}

		p.mu.Lock()
		p.last[provider.ID] = time.Now()
		p.mu.Unlock()
	}
}

// SyncProvider performs an immediate sync regardless of poll interval.
func (p *Poller) SyncProvider(ctx context.Context, providerID string) (*SyncResult, error) {
	var provider providerconfig.ProviderInstance
	if err := p.db.WithContext(ctx).
		Where("id = ? AND enabled = true", strings.TrimSpace(providerID)).
		First(&provider).Error; err != nil {
		return nil, err
	}
	return p.syncProvider(ctx, provider)
}

func (p *Poller) syncProvider(ctx context.Context, provider providerconfig.ProviderInstance) (*SyncResult, error) {
	result := &SyncResult{
		ProviderID:   provider.ID,
		ProviderName: provider.DisplayName,
		HealthStatus: providerconfig.ProviderHealthUnknown,
	}

	token, err := p.store.GetActiveToken(ctx, provider.ID)
	if err != nil {
		log.Printf("poller: get token for %s: %v", provider.DisplayName, err)
		msg := "failed to load provider token"
		_ = p.store.UpdateHealth(ctx, provider.ID, providerconfig.ProviderHealthFailed, msg)
		result.HealthStatus = providerconfig.ProviderHealthFailed
		result.HealthMessage = msg
		return result, err
	}

	healthMsg, healthErr := providerconfig.CheckProviderHealth(ctx, provider.Type, provider.BaseURL, provider.OwnerPath, token)
	if healthErr != nil {
		_ = p.store.UpdateHealth(ctx, provider.ID, providerconfig.ProviderHealthFailed, healthMsg)
		result.HealthStatus = providerconfig.ProviderHealthFailed
		result.HealthMessage = healthMsg
		return result, nil
	}

	client := providerconfig.NewProviderClient(provider.Type, provider.BaseURL, token)
	if client == nil {
		log.Printf("poller: unknown provider type %s for %s", provider.Type, provider.DisplayName)
		msg := "unsupported provider type"
		_ = p.store.UpdateHealth(ctx, provider.ID, providerconfig.ProviderHealthFailed, msg)
		result.HealthStatus = providerconfig.ProviderHealthFailed
		result.HealthMessage = msg
		return result, nil
	}

	// Fetch all repos (paginated)
	var allRepos []providers.RepoData
	var listErr error
	page := 1
	for {
		repos, pageInfo, err := client.ListPublicRepos(ctx, provider.OwnerPath, providers.ListOptions{
			Page:     page,
			PageSize: 100,
		})
		if err != nil {
			log.Printf("poller: list repos for %s page %d: %v", provider.DisplayName, page, err)
			listErr = err
			break
		}
		allRepos = append(allRepos, repos...)
		if !pageInfo.HasNextPage {
			break
		}
		page++
	}

	if listErr != nil {
		_ = p.store.UpdateHealth(ctx, provider.ID, providerconfig.ProviderHealthFailed, "failed to list repositories")
		result.HealthStatus = providerconfig.ProviderHealthFailed
		result.HealthMessage = "failed to list repositories"
		return result, nil
	}

	if len(allRepos) == 0 {
		_ = p.store.UpdateHealth(ctx, provider.ID, providerconfig.ProviderHealthHealthy, "no repositories found")
		result.HealthStatus = providerconfig.ProviderHealthHealthy
		result.HealthMessage = "no repositories found"
		return result, nil
	}

	var queued, skippedSame, skippedPending int
	for _, repo := range allRepos {
		if repo.DefaultBranch == "" || repo.IsEmpty {
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
			Provider:           provider.Type,
			ProviderInstanceID: provider.ID,
			Org:                org,
			Slug:               slug,
		})
		if err != nil {
			log.Printf("poller: upsert repo %s: %v", repo.FullPath, err)
			continue
		}

		// Skip commits that already have a finished run for this repo.
		if p.hasFinishedJobForCommit(ctx, repoRecord.ID, latestSHA) {
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

		tx := p.db.WithContext(ctx).Table("jobs").
			Clauses(clause.OnConflict{DoNothing: true}).
			Create(job)
		if tx.Error != nil {
			log.Printf("poller: create job for %s: %v", repo.FullPath, tx.Error)
			continue
		}
		if tx.RowsAffected == 0 {
			skippedPending++
			continue
		}

		queued++
	}

	if queued > 0 || skippedPending > 0 {
		log.Printf("poller: %s — queued=%d skipped_same=%d skipped_pending=%d total=%d",
			provider.DisplayName, queued, skippedSame, skippedPending, len(allRepos))
	}

	result.TotalRepos = len(allRepos)
	result.Queued = queued
	result.SkippedSame = skippedSame
	result.SkippedPending = skippedPending

	_ = p.store.UpdateHealth(ctx, provider.ID, providerconfig.ProviderHealthHealthy, "")
	result.HealthStatus = providerconfig.ProviderHealthHealthy
	result.HealthMessage = ""
	return result, nil
}

// hasFinishedJobForCommit checks if a CREATE_RUN job has already finished for repo+commit.
func (p *Poller) hasFinishedJobForCommit(ctx context.Context, repoID, commitSHA string) bool {
	if repoID == "" || commitSHA == "" {
		return false
	}

	var count int64
	p.db.WithContext(ctx).Table("jobs").
		Where("type = ?", jobs.JobTypeCreateRun).
		Where("finished_at IS NOT NULL").
		Where("payload->>'repo_id' = ?", repoID).
		Where("(commit_hash = ? OR payload->>'commit_sha' = ?)", commitSHA, commitSHA).
		Count(&count)
	return count > 0
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
