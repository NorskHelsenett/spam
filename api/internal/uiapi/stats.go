package uiapi

import (
	"net/http"

	"github.com/NorskHelsenett/spam/internal/acl"
	"github.com/NorskHelsenett/spam/internal/auth"
	"gorm.io/gorm"
)

// StatsResponse contains inventory statistics.
type StatsResponse struct {
	SBOMCount      int64 `json:"sbom_count"`
	ComponentCount int64 `json:"component_count"`
	RepoCount      int64 `json:"repo_count"`
	ImageCount     int64 `json:"image_count"`
}

// StatsHandler returns inventory statistics.
//
// Counts are scoped to the caller's readable resources so aggregates
// don't leak the existence of private repos. sbom_count and
// component_count are left unscoped for admin-or-wildcard callers
// today; restricted users see the repo_count and image_count they
// actually have access to, and sbom/component counts fall back to
// admin-gated values (0 for restricted users without wildcard). This
// is a deliberate trade — scoping SBOM/component aggregates requires
// a cross-table join that's not on Phase 3's critical path.
func StatsHandler(db *gorm.DB, authService *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if requireAuth(w, r, authService) == nil {
			return
		}

		repoClause, err := acl.ReadableRepoClause(r.Context(), acl.ProviderFromRequest(r), acl.SubjectFromRequest(r), "repos")
		if err != nil {
			http.Error(w, "query failed", http.StatusInternalServerError)
			return
		}
		repoWhere, repoArgs := aclWhereFragment(repoClause)

		subj := acl.SubjectFromRequest(r)
		var stats StatsResponse

		// Unrestricted callers run the original query so sbom_count
		// and component_count are accurate.
		if repoClause.Unrestricted {
			if err := db.WithContext(r.Context()).Raw(`
				SELECT
					(SELECT COUNT(*) FROM sboms) AS sbom_count,
					(SELECT COUNT(DISTINCT kind || ':' || package_name)
					 FROM sbom_component_view
					 WHERE is_root = false AND package_name IS NOT NULL) AS component_count,
					(SELECT COUNT(*) FROM repos) AS repo_count,
					(SELECT COUNT(*) FROM image_digests) AS image_count
			`).Scan(&stats).Error; err != nil {
				http.Error(w, "query failed", http.StatusInternalServerError)
				return
			}
			writeJSON(w, http.StatusOK, stats)
			return
		}

		// Restricted callers: count only their readable repos +
		// images bound to verified-source readable repos. Admin-only
		// data (sboms, components) collapses to 0 here.
		imageArgs := append([]any{}, repoArgs...)
		_ = subj
		if err := db.WithContext(r.Context()).Raw(`
			SELECT
				0 AS sbom_count,
				0 AS component_count,
				(SELECT COUNT(*) FROM repos WHERE `+repoWhere+`) AS repo_count,
				(SELECT COUNT(*) FROM image_digests d
				   WHERE d.verified_source = true
				     AND d.source_repo_id <> ''
				     AND d.source_repo_id IN (SELECT id FROM repos WHERE `+repoWhere+`)) AS image_count
		`, append(repoArgs, imageArgs...)...).Scan(&stats).Error; err != nil {
			http.Error(w, "query failed", http.StatusInternalServerError)
			return
		}

		writeJSON(w, http.StatusOK, stats)
	}
}
