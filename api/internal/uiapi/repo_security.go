package uiapi

import (
	"encoding/json"
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
		if requireAuth(w, r, authService) == nil {
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
			if err := db.WithContext(r.Context()).Table("sbom_component_view").
				Where("sbom_id = ? AND is_root = false", sbomID).
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

// SecretFinding is a single Gitleaks finding extracted from stored JSON.
type SecretFinding struct {
	RuleID      string `json:"rule_id"`
	Description string `json:"description"`
	File        string `json:"file"`
	StartLine   int    `json:"start_line"`
	Match       string `json:"match"`
}

// RepoSecretsListHandler returns individual secret findings for a repo's latest scan.
// GET /api/repos/secrets/list?repo_id=<uuid>
func RepoSecretsListHandler(db *gorm.DB, authService *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if requireAuth(w, r, authService) == nil {
			return
		}

		repoID := r.URL.Query().Get("repo_id")
		if repoID == "" {
			http.Error(w, "repo_id required", http.StatusBadRequest)
			return
		}

		// Cast JSONB to text so GORM can scan it into a plain string reliably.
		// Try by repo_id first; fall back to the latest run tied to this repo via jobs table.
		var rawFindings string
		res := db.WithContext(r.Context()).Table("run_secrets").
			Select("findings::text").
			Where("repo_id = ?", repoID).
			Order("created_at DESC").
			Limit(1).
			Scan(&rawFindings)
		if res.Error != nil || res.RowsAffected == 0 || rawFindings == "" {
			// Fallback: find the latest run_id for this repo and query by that
			var runID string
			db.WithContext(r.Context()).Table("jobs").
				Select("id").
				Where("repo_id = ?", repoID).
				Order("created_at DESC").
				Limit(1).
				Scan(&runID)
			if runID != "" {
				db.WithContext(r.Context()).Table("run_secrets").
					Select("findings::text").
					Where("run_id = ?", runID).
					Order("created_at DESC").
					Limit(1).
					Scan(&rawFindings)
			}
		}
		if rawFindings == "" {
			writeJSON(w, http.StatusOK, []SecretFinding{})
			return
		}

		// Gitleaks output: array of objects with RuleID, Description, File, StartLine, Match
		var raw []struct {
			RuleID      string `json:"RuleID"`
			Description string `json:"Description"`
			File        string `json:"File"`
			StartLine   int    `json:"StartLine"`
			Match       string `json:"Match"`
		}
		if err := json.Unmarshal([]byte(rawFindings), &raw); err != nil {
			writeJSON(w, http.StatusOK, []SecretFinding{})
			return
		}

		out := make([]SecretFinding, 0, len(raw))
		for _, f := range raw {
			out = append(out, SecretFinding{
				RuleID:      f.RuleID,
				Description: f.Description,
				File:        f.File,
				StartLine:   f.StartLine,
				Match:       f.Match,
			})
		}
		writeJSON(w, http.StatusOK, out)
	}
}
