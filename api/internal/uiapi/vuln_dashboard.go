package uiapi

import (
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/NorskHelsenett/spam/internal/auth"
	"github.com/NorskHelsenett/spam/internal/vulnmetrics"
	"gorm.io/gorm"
)

// VulnSummaryHandler returns overall vulnerability counts and last scan time.
//
// GET /api/vuln/summary
func VulnSummaryHandler(db *gorm.DB, authService *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if requireAuth(w, r, authService) == nil {
			return
		}

		summary, err := vulnmetrics.LoadSummary(r.Context(), db)
		if err != nil {
			http.Error(w, "failed to load vulnerability summary", http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, summary)
	}
}

// VulnReposHandler returns per-repo vulnerability counts sorted by severity.
//
// GET /api/vuln/repos
func VulnReposHandler(db *gorm.DB, authService *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if requireAuth(w, r, authService) == nil {
			return
		}

		type repoRow struct {
			RepoID        string     `json:"repo_id"`
			RepoSlug      string     `json:"repo_slug"`
			CriticalCount int        `json:"critical_count"`
			HighCount     int        `json:"high_count"`
			MediumCount   int        `json:"medium_count"`
			LowCount      int        `json:"low_count"`
			UnknownCount  int        `json:"unknown_count"`
			LastScannedAt *time.Time `json:"last_scanned_at"`
		}

		var rows []repoRow
		db.WithContext(r.Context()).Raw(`
			SELECT
				repo_id,
				MAX(repo_slug)                                                    AS repo_slug,
				COUNT(*) FILTER (WHERE severity = 'CRITICAL')                    AS critical_count,
				COUNT(*) FILTER (WHERE severity = 'HIGH')                        AS high_count,
				COUNT(*) FILTER (WHERE severity = 'MEDIUM')                      AS medium_count,
				COUNT(*) FILTER (WHERE severity = 'LOW')                         AS low_count,
				COUNT(*) FILTER (WHERE severity NOT IN ('CRITICAL','HIGH','MEDIUM','LOW')) AS unknown_count,
				MAX(scanned_at)                                                   AS last_scanned_at
			FROM view_unified_repositories_vulnerabilities
			GROUP BY repo_id
			ORDER BY critical_count DESC, high_count DESC, medium_count DESC
		`).Scan(&rows)

		if rows == nil {
			rows = []repoRow{}
		}

		writeJSON(w, http.StatusOK, rows)
	}
}

// VulnListHandler returns individual vulnerabilities extracted from Trivy raw JSON.
//
// GET /api/vuln/list?severity=CRITICAL,HIGH&limit=200
func VulnListHandler(db *gorm.DB, authService *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if requireAuth(w, r, authService) == nil {
			return
		}

		limit := 5000
		repoID := r.URL.Query().Get("repo_id")

		type vulnRow struct {
			RepoID           string `json:"repo_id"`
			RepoSlug         string `json:"repo_slug"`
			VulnID           string `json:"vuln_id"`
			Severity         string `json:"severity"`
			PkgName          string `json:"pkg_name"`
			InstalledVersion string `json:"installed_version"`
			FixedVersion     string `json:"fixed_version"`
			Title            string `json:"title"`
			Description      string `json:"description"`
			Source           string `json:"source"`
		}

		var rows []vulnRow
		var args []any
		where := ""
		if repoID != "" {
			where = "WHERE repo_id = ?"
			args = append(args, repoID)
		}
		args = append(args, limit)

		query := fmt.Sprintf(`
			SELECT repo_id, repo_slug, vuln_id, severity, pkg_name, installed_version, fixed_version, title, description, source
			FROM view_unified_repositories_vulnerabilities
			%s
			ORDER BY
				CASE severity
					WHEN 'CRITICAL' THEN 1
					WHEN 'HIGH'     THEN 2
					WHEN 'MEDIUM'   THEN 3
					WHEN 'LOW'      THEN 4
					ELSE 5
				END,
				vuln_id
			LIMIT ?
		`, where)

		db.WithContext(r.Context()).Raw(query, args...).Scan(&rows)

		if rows == nil {
			rows = []vulnRow{}
		}

		writeJSON(w, http.StatusOK, rows)
	}
}

// VulnTrendHandler returns daily aggregate vulnerability counts for the last N days.
//
// GET /api/vuln/trend?days=30
func VulnTrendHandler(db *gorm.DB, authService *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if requireAuth(w, r, authService) == nil {
			return
		}

		days := 30
		if d := r.URL.Query().Get("days"); d != "" {
			if v, err := strconv.Atoi(d); err == nil && v > 0 && v <= 365 {
				days = v
			}
		}

		rows, err := vulnmetrics.LoadTrend(r.Context(), db, days)
		if err != nil {
			http.Error(w, "failed to load vulnerability trend", http.StatusInternalServerError)
			return
		}

		writeJSON(w, http.StatusOK, rows)
	}
}
