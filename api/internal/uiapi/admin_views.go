package uiapi

import (
	"net/http"
	"time"

	"github.com/NorskHelsenett/spam/internal/auth"
	spdb "github.com/NorskHelsenett/spam/internal/db"
	"gorm.io/gorm"
)

type viewRefreshStatus struct {
	Name        string    `json:"name"`
	RefreshedAt time.Time `json:"refreshed_at"`
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

// AdminViewsStatusHandler returns materialized view refresh timestamps.
func AdminViewsStatusHandler(db *gorm.DB, authService *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, err := authService.RequireAdmin(r); err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		rows := make([]viewRefreshStatus, 0)
		if err := db.WithContext(r.Context()).
			Table("materialized_view_refreshes").
			Order("name ASC").
			Scan(&rows).Error; err != nil {
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
