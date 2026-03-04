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
// GET /api/repos/contributors?repo_id=<uuid>
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

		// Look up provider type, org, slug, and provider_instance_id from the repo UUID.
		var repo struct {
			Provider           string
			Org                string
			Slug               string
			ProviderInstanceID *string
		}
		if err := db.WithContext(r.Context()).Table("repos").
			Select("provider, org, slug, provider_instance_id").
			Where("id = ?", repoID).
			First(&repo).Error; err != nil {
			writeJSON(w, http.StatusOK, RepoContributorsResponse{Contributors: []providers.ContributorInfo{}})
			return
		}

		providerType := repo.Provider
		repoPath := repo.Org + "/" + repo.Slug
		providerID := ""
		if repo.ProviderInstanceID != nil {
			providerID = *repo.ProviderInstanceID
		}

		// Cache check (keyed by repo UUID for uniqueness).
		cacheKey := fmt.Sprintf("contributors:%s", repoID)
		if cached, ok, _ := cache.GetJSON[RepoContributorsResponse](r.Context(), c, cacheKey); ok {
			writeJSON(w, http.StatusOK, cached)
			return
		}

		baseURL, token, err := store.ResolveProviderAccess(r.Context(), providerID, providerType, "", repoPath)
		if err != nil {
			http.Error(w, "failed to load provider token", http.StatusInternalServerError)
			return
		}

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
