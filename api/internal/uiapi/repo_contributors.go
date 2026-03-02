package uiapi

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/NorskHelsenett/spam/internal/auth"
	"github.com/NorskHelsenett/spam/internal/cache"
	"github.com/NorskHelsenett/spam/internal/providerconfig"
	"github.com/NorskHelsenett/spam/internal/providers"
	"gorm.io/gorm"
)

const contributorCacheTTL = 15 * time.Minute

type RepoContributorsResponse struct {
	Contributors []providers.ContributorInfo `json:"contributors"`
}

// RepoContributorsHandler returns the top contributors for a repo, fetched
// from the appropriate provider API and cached for contributorCacheTTL.
//
// GET /api/repos/contributors?repo_id=provider:org:slug&provider_id=<uuid>
func RepoContributorsHandler(db *gorm.DB, authService *auth.Service, store *providerconfig.Store, c cache.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if requireAuth(w, r, authService) == nil {
			return
		}

		repoID := strings.TrimSpace(r.URL.Query().Get("repo_id"))
		if repoID == "" {
			http.Error(w, "repo_id required", http.StatusBadRequest)
			return
		}

		parts := strings.SplitN(repoID, ":", 3)
		if len(parts) != 3 {
			http.Error(w, "repo_id must be provider:org:slug", http.StatusBadRequest)
			return
		}
		providerType, org, slug := parts[0], parts[1], parts[2]
		repoPath := org + "/" + slug

		// Cache check
		cacheKey := fmt.Sprintf("contributors:%s", repoID)
		if cached, ok, _ := cache.GetJSON[RepoContributorsResponse](r.Context(), c, cacheKey); ok {
			writeJSON(w, http.StatusOK, cached)
			return
		}

		token, err := resolveProviderTokenByBaseURL(r, store, providerType, repoPath)
		if err != nil {
			http.Error(w, "failed to load provider token", http.StatusInternalServerError)
			return
		}

		baseURL := r.URL.Query().Get("base_url")
		client := providerconfig.NewProviderClient(providerType, baseURL, token)
		if client == nil {
			writeJSON(w, http.StatusOK, RepoContributorsResponse{Contributors: []providers.ContributorInfo{}})
			return
		}

		contribs, err := client.GetContributors(r.Context(), repoPath, 5)
		if err != nil {
			// Non-fatal: return empty list rather than an error
			contribs = []providers.ContributorInfo{}
		}
		if contribs == nil {
			contribs = []providers.ContributorInfo{}
		}

		resp := RepoContributorsResponse{Contributors: contribs}
		_ = cache.SetJSON(r.Context(), c, cacheKey, resp, contributorCacheTTL)
		writeJSON(w, http.StatusOK, resp)
	}
}
