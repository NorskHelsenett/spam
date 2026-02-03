package uiapi

import (
	"net/http"
	"strings"

	"github.com/NorskHelsenett/spam/internal/auth"
	"gorm.io/gorm"
)

// RepoSecurityCountsResponse contains per-repo SBOM and secrets counts.
type RepoSecurityCountsResponse struct {
	RepoID              string `json:"repo_id"`
	SBOMDependencyCount int64  `json:"sbom_dependency_count"`
	SecretsFindingCount int64  `json:"secrets_count"`
}

// RepoSecurityCountsHandler returns SBOM dependency and secrets counts for a repo.
// GET /api/repos/security?repo_id=provider:org:slug
func RepoSecurityCountsHandler(db *gorm.DB, authService *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, err := authService.LoadSession(r); err != nil {
			http.Error(w, "unauthenticated", http.StatusUnauthorized)
			return
		}

		repoID := r.URL.Query().Get("repo_id")
		if repoID == "" {
			http.Error(w, "repo_id required", http.StatusBadRequest)
			return
		}

		var sbomID string
		if err := db.WithContext(r.Context()).Table("sbom_bindings").
			Select("sbom_id").
			Where("asset_ref_id = ?", repoID).
			Order("created_at DESC").
			Limit(1).
			Scan(&sbomID).Error; err != nil {
			http.Error(w, "failed to fetch sbom binding", http.StatusInternalServerError)
			return
		}

		if sbomID == "" {
			parts := strings.SplitN(repoID, ":", 3)
			if len(parts) == 3 {
				var repo struct {
					ID string
				}
				if err := db.WithContext(r.Context()).Table("repos").
					Select("id").
					Where("provider = ? AND org = ? AND slug = ?", parts[0], parts[1], parts[2]).
					First(&repo).Error; err == nil {
					var commitID string
					if err := db.WithContext(r.Context()).Table("repo_commits").
						Select("id").
						Where("repo_id = ?", repo.ID).
						Order("created_at DESC").
						Limit(1).
						Scan(&commitID).Error; err == nil && commitID != "" {
						_ = db.WithContext(r.Context()).Table("sbom_bindings").
							Select("sbom_id").
							Where("asset_ref_id = ?", commitID).
							Order("created_at DESC").
							Limit(1).
							Scan(&sbomID).Error
					}
				}
			}
		}

		var sbomDeps int64
		if sbomID != "" {
			if err := db.WithContext(r.Context()).Table("sbom_components").
				Where("sbom_id = ?", sbomID).
				Count(&sbomDeps).Error; err != nil {
				http.Error(w, "failed to fetch sbom components", http.StatusInternalServerError)
				return
			}
		}

		var secretsCount int64
		repoDBID := ""
		if parts := strings.SplitN(repoID, ":", 3); len(parts) == 3 {
			var repo struct {
				ID string
			}
			if err := db.WithContext(r.Context()).Table("repos").
				Select("id").
				Where("provider = ? AND org = ? AND slug = ?", parts[0], parts[1], parts[2]).
				First(&repo).Error; err == nil {
				repoDBID = repo.ID
			}
		}

		secretsQuery := db.WithContext(r.Context()).Table("run_secrets").
			Select("finding_count").
			Order("created_at DESC").
			Limit(1)
		if repoDBID != "" {
			secretsQuery = secretsQuery.Where("repo_id = ?", repoDBID)
		} else {
			secretsQuery = secretsQuery.Where("repo_id = ?", repoID)
		}

		if err := secretsQuery.Scan(&secretsCount).Error; err != nil {
			http.Error(w, "failed to fetch secrets count", http.StatusInternalServerError)
			return
		}

		writeJSON(w, http.StatusOK, RepoSecurityCountsResponse{
			RepoID:              repoID,
			SBOMDependencyCount: sbomDeps,
			SecretsFindingCount: secretsCount,
		})
	}
}
