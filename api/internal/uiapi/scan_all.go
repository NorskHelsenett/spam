package uiapi

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/NorskHelsenett/spam/internal/assets"
	"github.com/NorskHelsenett/spam/internal/auth"
	"github.com/NorskHelsenett/spam/internal/jobs"
	"github.com/NorskHelsenett/spam/internal/providerconfig"
	"github.com/NorskHelsenett/spam/internal/providers"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// ScanAllRequest is the request body for scanning all repos.
type ScanAllRequest struct {
	Provider         string `json:"provider"`          // "github", "gitlab", "gitea", "forgejo"
	Owner            string `json:"owner"`             // For GitHub or Gitea
	Group            string `json:"group"`             // For GitLab
	BaseURL          string `json:"base_url"`          // For custom instances
	IncludeSubgroups bool   `json:"include_subgroups"` // For GitLab
	ProviderID       string `json:"provider_id"`       // Optional provider instance id
	OnlyNew          bool   `json:"only_new"`          // Skip repos that already have a successful run
}

// ScanAllResponse is the response for scan all operation.
type ScanAllResponse struct {
	TotalQueued int      `json:"total_queued"`
	Errors      []string `json:"errors,omitempty"`
}

// ScanAllHandler handles queueing SBOM generation jobs for all repos in a provider/owner/group.
// POST /api/scan-all — streams progress via SSE (event: progress / event: done).
func ScanAllHandler(db *gorm.DB, authService *auth.Service, store *providerconfig.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if requireAdmin(w, r, authService) == nil {
			return
		}

		var req ScanAllRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}

		if req.Provider == "" {
			http.Error(w, "provider is required", http.StatusBadRequest)
			return
		}

		// Resolve token, display name, and baseURL from the DB while still within the request context.
		// baseURL must come from the DB to prevent SSRF — never trust req.BaseURL.
		token := ""
		label := req.Provider
		baseURL := ""
		if store != nil && req.ProviderID != "" {
			if t, err := store.GetActiveToken(r.Context(), req.ProviderID); err == nil {
				token = t
			}
			if provs, err := store.ListAdmin(r.Context()); err == nil {
				for _, p := range provs {
					if p.ID == req.ProviderID {
						label = p.DisplayName
						baseURL = p.BaseURL
						break
					}
				}
			}
		}

		// Set SSE headers — no timeout middleware on this route.
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		w.Header().Set("X-Accel-Buffering", "no")

		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "streaming unsupported", http.StatusInternalServerError)
			return
		}

		// onProgress is called after each page is fetched and queued.
		// It must only be called from the scan functions' main loop (not goroutines).
		onProgress := func(totalQueued int) {
			data, _ := json.Marshal(map[string]int{"queued": totalQueued})
			fmt.Fprintf(w, "event: progress\ndata: %s\n\n", data)
			flusher.Flush()
		}

		ctx := r.Context()
		var totalQueued int
		var allErrors []string

		switch req.Provider {
		case "github":
			totalQueued, allErrors = scanAllGitHub(ctx, db, req.Owner, baseURL, req.ProviderID, token, label, req.OnlyNew, onProgress)
		case "gitlab":
			totalQueued, allErrors = scanAllGitLab(ctx, db, req.Group, baseURL, req.IncludeSubgroups, req.ProviderID, token, label, req.OnlyNew, onProgress)
		case "gitea", "forgejo":
			totalQueued, allErrors = scanAllGitea(ctx, db, req.Owner, baseURL, req.ProviderID, token, label, req.OnlyNew, onProgress)
		}

		// Send done event with final totals.
		doneData, _ := json.Marshal(ScanAllResponse{TotalQueued: totalQueued, Errors: allErrors})
		fmt.Fprintf(w, "event: done\ndata: %s\n\n", doneData)
		flusher.Flush()
	}
}

// scanAllGitHub fetches all GitHub repos page-by-page and queues them for scanning.
func scanAllGitHub(ctx context.Context, db *gorm.DB, owner, baseURL, providerID, token, label string, onlyNew bool, onProgress func(int)) (int, []string) {
	if owner == "" {
		return 0, []string{"owner is required"}
	}

	client := providers.NewGitHubClient(baseURL, token)
	var allErrors []string
	var totalQueued int
	page := 1
	const pageSize = 100

	for {
		repos, pageInfo, err := client.ListPublicRepos(ctx, owner, providers.ListOptions{
			Page:     page,
			PageSize: pageSize,
		})
		if err != nil {
			allErrors = append(allErrors, fmt.Sprintf("Failed to fetch page %d: %v", page, err))
			break
		}
		totalQueued += queueRepos(ctx, db, repos, "github", baseURL, providerID, label, onlyNew, page, &allErrors)
		onProgress(totalQueued)
		if !pageInfo.HasNextPage {
			break
		}
		page++
	}

	log.Printf("Queued %d repos for %s scanning", totalQueued, label)
	return totalQueued, allErrors
}

// scanAllGitLab fetches all GitLab projects page-by-page and queues them for scanning.
func scanAllGitLab(ctx context.Context, db *gorm.DB, group, baseURL string, includeSubgroups bool, providerID, token, label string, onlyNew bool, onProgress func(int)) (int, []string) {
	client := providers.NewGitLabClient(baseURL, token)
	var allErrors []string
	var totalQueued int
	page := 1
	const pageSize = 100

	for {
		projects, pageInfo, err := client.ListPublicProjects(ctx, group, providers.ListOptions{
			Page:             page,
			PageSize:         pageSize,
			IncludeSubgroups: includeSubgroups,
		})
		if err != nil {
			allErrors = append(allErrors, fmt.Sprintf("Failed to fetch page %d: %v", page, err))
			break
		}
		totalQueued += queueRepos(ctx, db, projects, "gitlab", baseURL, providerID, label, onlyNew, page, &allErrors)
		onProgress(totalQueued)
		if !pageInfo.HasNextPage {
			break
		}
		page++
	}

	log.Printf("Queued %d projects for %s scanning", totalQueued, label)
	return totalQueued, allErrors
}

// scanAllGitea fetches all Gitea/Forgejo repos page-by-page and queues them for scanning.
func scanAllGitea(ctx context.Context, db *gorm.DB, owner, baseURL, providerID, token, label string, onlyNew bool, onProgress func(int)) (int, []string) {
	if baseURL == "" {
		return 0, []string{"base_url is required for Gitea/Forgejo"}
	}

	client := providers.NewGiteaClient(baseURL, token)
	var allErrors []string
	var totalQueued int
	page := 1
	const pageSize = 100

	for {
		repos, pageInfo, err := client.ListPublicRepos(ctx, owner, providers.ListOptions{
			Page:     page,
			PageSize: pageSize,
		})
		if err != nil {
			allErrors = append(allErrors, fmt.Sprintf("Failed to fetch page %d: %v", page, err))
			break
		}
		totalQueued += queueRepos(ctx, db, repos, "gitea", baseURL, providerID, label, onlyNew, page, &allErrors)
		onProgress(totalQueued)
		if !pageInfo.HasNextPage {
			break
		}
		page++
	}

	log.Printf("Queued %d repos for %s scanning", totalQueued, label)
	return totalQueued, allErrors
}

// queueRepos creates jobs for all repos in parallel batches.
func queueRepos(ctx context.Context, db *gorm.DB, repos []providers.RepoData, provider string, baseURL string, providerID string, label string, onlyNew bool, page int, errors *[]string) int {
	const batchSize = 10
	var mu sync.Mutex
	var queued, skipped int

	for i := 0; i < len(repos); i += batchSize {
		end := i + batchSize
		if end > len(repos) {
			end = len(repos)
		}

		batch := repos[i:end]
		var wg sync.WaitGroup

		for _, repo := range batch {
			wg.Add(1)
			go func(r providers.RepoData) {
				defer wg.Done()
				if r.IsDisabled || r.IsEmpty || r.DefaultBranch == "" {
					mu.Lock()
					skipped++
					mu.Unlock()
					return
				}

				// Build clone URL
				cloneURL := buildCloneURL(provider, r.FullPath, baseURL)
				if cloneURL == "" {
					mu.Lock()
					*errors = append(*errors, fmt.Sprintf("%s: invalid clone URL", r.Name))
					mu.Unlock()
					return
				}

				// Resolve provider instance ID before upserting the repo
				resolvedProviderID := providerID
				if resolvedProviderID == "" {
					if match, err := providerconfig.FindProviderMatch(ctx, db, provider, baseURL, r.FullPath); err == nil && match != nil {
						resolvedProviderID = match.ID
					}
				}

				// Upsert repo
				fullPath := strings.Trim(r.FullPath, "/")
				lastSlash := strings.LastIndex(fullPath, "/")
				org := ""
				slug := fullPath
				if lastSlash >= 0 {
					org = fullPath[:lastSlash]
					slug = fullPath[lastSlash+1:]
				}

				repoRecord, err := assets.UpsertRepo(ctx, db, assets.RepoInput{
					Provider:           provider,
					Org:                org,
					Slug:               slug,
					ExternalID:         r.ExternalID,
					ProviderInstanceID: resolvedProviderID,
				})
				if err != nil {
					mu.Lock()
					*errors = append(*errors, fmt.Sprintf("%s: %v", r.Name, err))
					mu.Unlock()
					return
				}

				// Skip if onlyNew and repo already has a successful run
				if onlyNew {
					var existingCount int64
					db.WithContext(ctx).Table("jobs").
						Where("type = ? AND status = ? AND payload->>'repo_id' = ?",
							jobs.JobTypeCreateRun, jobs.JobStatusSucceeded, repoRecord.ID).
						Count(&existingCount)
					if existingCount > 0 {
						return
					}
				}

				// Create job payload
				payload := jobs.CreateRunPayload{
					RepoID:       repoRecord.ID,
					ProviderID:   resolvedProviderID,
					Provider:     provider,
					CloneURL:     cloneURL,
					Ref:          r.DefaultBranch,
					RepoDisabled: r.IsDisabled,
				}

				payloadBytes, err := json.Marshal(payload)
				if err != nil {
					mu.Lock()
					*errors = append(*errors, fmt.Sprintf("%s: %v", r.Name, err))
					mu.Unlock()
					return
				}

				// Create job record
				jobID := uuid.New().String()
				now := time.Now()
				job := map[string]interface{}{
					"id":           jobID,
					"type":         jobs.JobTypeCreateRun,
					"status":       "QUEUED",
					"payload":      payloadBytes,
					"attempts":     0,
					"max_attempts": 3,
					"run_at":       now,
					"created_at":   now,
					"updated_at":   now,
				}

				if err := db.WithContext(ctx).Table("jobs").Create(job).Error; err != nil {
					mu.Lock()
					*errors = append(*errors, fmt.Sprintf("%s: %v", r.Name, err))
					mu.Unlock()
					return
				}

				mu.Lock()
				queued++
				mu.Unlock()
			}(repo)
		}

		wg.Wait()
	}

	log.Printf("Queued %d/%d repos for %s scanning (page %d, skipped %d disabled/empty/no-branch, %d errors)", queued, len(repos), label, page, skipped, len(*errors))
	return queued
}
