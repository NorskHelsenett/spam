package uiapi

import (
	"net/http"

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
func StatsHandler(db *gorm.DB, authService *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if requireAuth(w, r, authService) == nil {
			return
		}

		var stats StatsResponse

		if err := db.WithContext(r.Context()).Table("sboms").Count(&stats.SBOMCount).Error; err != nil {
			http.Error(w, "query failed", http.StatusInternalServerError)
			return
		}

		if err := db.WithContext(r.Context()).Raw(`
			SELECT COUNT(DISTINCT kind || ':' || package_name)
			FROM sbom_component_view
			WHERE is_root = false AND package_name IS NOT NULL
		`).Scan(&stats.ComponentCount).Error; err != nil {
			http.Error(w, "query failed", http.StatusInternalServerError)
			return
		}

		if err := db.WithContext(r.Context()).Table("repos").Count(&stats.RepoCount).Error; err != nil {
			http.Error(w, "query failed", http.StatusInternalServerError)
			return
		}

		if err := db.WithContext(r.Context()).Table("image_digests").Count(&stats.ImageCount).Error; err != nil {
			http.Error(w, "query failed", http.StatusInternalServerError)
			return
		}

		writeJSON(w, http.StatusOK, stats)
	}
}
