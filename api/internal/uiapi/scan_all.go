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
}

// ScanAllResponse is the response for scan all operation.
type ScanAllResponse struct {
	TotalQueued int      `json:"total_queued"`
	Errors      []string `json:"errors,omitempty"`
}

// ScanAllHandler handles queueing SBOM generation jobs for all repos in a provider/owner/group.
// POST /api/scan-all
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

		ctx := r.Context()
		var totalQueued int
		var errors []string

		// Resolve token and display name from the provider instance if one is configured.
		token := ""
		label := req.Provider
		if store != nil && req.ProviderID != "" {
			if t, err := store.GetActiveToken(ctx, req.ProviderID); err == nil {
				token = t
			}
			if providers, err := store.ListAdmin(ctx); err == nil {
				for _, p := range providers {
					if p.ID == req.ProviderID {
						label = p.DisplayName
						break
					}
				}
			}
		}

		switch req.Provider {
		case "github":
			totalQueued, errors = scanAllGitHub(ctx, db, req.Owner, req.ProviderID, token, label)
		case "gitlab":
			totalQueued, errors = scanAllGitLab(ctx, db, req.Group, req.BaseURL, req.IncludeSubgroups, req.ProviderID, token, label)
		case "gitea", "forgejo":
			totalQueued, errors = scanAllGitea(ctx, db, req.Owner, req.BaseURL, req.ProviderID, token, label)
		default:
			http.Error(w, fmt.Sprintf("unsupported provider: %s", req.Provider), http.StatusBadRequest)
			return
		}

		writeJSON(w, http.StatusOK, ScanAllResponse{
			TotalQueued: totalQueued,
			Errors:      errors,
		})
	}
}

// scanAllGitHub fetches all GitHub repos and queues them for scanning.
func scanAllGitHub(ctx context.Context, db *gorm.DB, owner string, providerID string, token string, label string) (int, []string) {
	if owner == "" {
		return 0, []string{"owner is required"}
	}

	client := providers.NewGitHubClient("", token)
	var allRepos []providers.RepoData
	var errors []string

	page := 1
	const pageSize = 100

	for {
		repos, pageInfo, err := client.ListPublicRepos(ctx, owner, providers.ListOptions{
			Page:     page,
			PageSize: pageSize,
		})
		if err != nil {
			errors = append(errors, fmt.Sprintf("Failed to fetch page %d: %v", page, err))
			break
		}
		allRepos = append(allRepos, repos...)
		if !pageInfo.HasNextPage {
			break
		}
		page++
	}

	queued := queueRepos(ctx, db, allRepos, "github", "", providerID, label, &errors)
	return queued, errors
}

// scanAllGitLab fetches all GitLab projects and queues them for scanning.
func scanAllGitLab(ctx context.Context, db *gorm.DB, group string, baseURL string, includeSubgroups bool, providerID string, token string, label string) (int, []string) {
	client := providers.NewGitLabClient(baseURL, token)
	var allProjects []providers.RepoData
	var errors []string

	page := 1
	const pageSize = 100

	for {
		projects, pageInfo, err := client.ListPublicProjects(ctx, group, providers.ListOptions{
			Page:             page,
			PageSize:         pageSize,
			IncludeSubgroups: includeSubgroups,
		})
		if err != nil {
			errors = append(errors, fmt.Sprintf("Failed to fetch page %d: %v", page, err))
			break
		}
		allProjects = append(allProjects, projects...)
		if !pageInfo.HasNextPage {
			break
		}
		page++
	}

	queued := queueRepos(ctx, db, allProjects, "gitlab", baseURL, providerID, label, &errors)
	return queued, errors
}

// scanAllGitea fetches all Gitea/Forgejo repos and queues them for scanning.
func scanAllGitea(ctx context.Context, db *gorm.DB, owner string, baseURL string, providerID string, token string, label string) (int, []string) {
	if baseURL == "" {
		return 0, []string{"base_url is required for Gitea/Forgejo"}
	}

	client := providers.NewGiteaClient(baseURL, token)
	var allRepos []providers.RepoData
	var errors []string

	page := 1
	const pageSize = 100

	for {
		repos, pageInfo, err := client.ListPublicRepos(ctx, owner, providers.ListOptions{
			Page:     page,
			PageSize: pageSize,
		})
		if err != nil {
			errors = append(errors, fmt.Sprintf("Failed to fetch page %d: %v", page, err))
			break
		}
		allRepos = append(allRepos, repos...)
		if !pageInfo.HasNextPage {
			break
		}
		page++
	}

	queued := queueRepos(ctx, db, allRepos, "gitea", baseURL, providerID, label, &errors)
	return queued, errors
}

// queueRepos creates jobs for all repos in parallel batches.
func queueRepos(ctx context.Context, db *gorm.DB, repos []providers.RepoData, provider string, baseURL string, providerID string, label string, errors *[]string) int {
	const batchSize = 10
	var mu sync.Mutex
	var queued int

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

	log.Printf("Queued %d/%d repos for %s scanning", queued, len(repos), label)
	return queued
}
