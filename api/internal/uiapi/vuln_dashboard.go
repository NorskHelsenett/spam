package uiapi

import (
	"net/http"
	"strconv"

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

		rows, err := vulnmetrics.LoadRepos(r.Context(), db)
		if err != nil {
			http.Error(w, "failed to load vulnerability repos", http.StatusInternalServerError)
			return
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

		repoID := r.URL.Query().Get("repo_id")
		rows, err := vulnmetrics.LoadList(r.Context(), db)
		if err != nil {
			http.Error(w, "failed to load vulnerability list", http.StatusInternalServerError)
			return
		}
		if repoID != "" {
			filtered := make([]vulnmetrics.VulnRow, 0, len(rows))
			for _, row := range rows {
				if row.RepoID == repoID {
					filtered = append(filtered, row)
				}
			}
			rows = filtered
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
