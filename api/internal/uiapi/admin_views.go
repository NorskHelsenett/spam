package uiapi

import (
	"net/http"
	"time"

	"github.com/NorskHelsenett/spam/internal/auth"
	spdb "github.com/NorskHelsenett/spam/internal/db"
	"gorm.io/gorm"
)

type viewRefreshStatus struct {
	Name        string     `json:"name"`
	Populated   bool       `json:"populated"`
	RefreshedAt *time.Time `json:"refreshed_at,omitempty"`
}

// AdminViewsRefreshHandler refreshes SBOM materialized views.
func AdminViewsRefreshHandler(db *gorm.DB, authService *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, err := authService.RequireAdmin(r); err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		if err := spdb.RefreshMaterializedViews(r.Context(), db); err != nil {
			http.Error(w, "refresh failed", http.StatusInternalServerError)
			return
		}

		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	}
}

// AdminViewsStatusHandler returns the per-MV populated state and last
// refresh timestamp. Joins pg_matviews to materialized_view_refreshes so
// MVs created WITH NO DATA still appear (with populated=false and a
// null timestamp) — the admin UI treats that as the signal that the
// first-populate goroutine hasn't won the advisory lock yet.
func AdminViewsStatusHandler(db *gorm.DB, authService *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, err := authService.RequireAdmin(r); err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		rows := make([]viewRefreshStatus, 0)
		if err := db.WithContext(r.Context()).Raw(`
			SELECT
			    pm.matviewname            AS name,
			    pm.ispopulated            AS populated,
			    mvr.refreshed_at          AS refreshed_at
			FROM pg_matviews pm
			LEFT JOIN materialized_view_refreshes mvr
			       ON mvr.name = pm.matviewname
			WHERE pm.schemaname = current_schema()
			ORDER BY pm.matviewname ASC
		`).Scan(&rows).Error; err != nil {
			http.Error(w, "query failed", http.StatusInternalServerError)
			return
		}

		writeJSON(w, http.StatusOK, map[string][]viewRefreshStatus{"views": rows})
	}
}

// AdminCacheClearHandler clears all kv_store cache entries.
func AdminCacheClearHandler(db *gorm.DB, authService *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, err := authService.RequireAdmin(r); err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		if err := db.WithContext(r.Context()).Exec("DELETE FROM kv_store").Error; err != nil {
			http.Error(w, "failed to clear cache", http.StatusInternalServerError)
			return
		}

		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	}
}
