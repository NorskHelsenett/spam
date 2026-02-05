package uiapi

import (
	"net/http"
	"strconv"

	"github.com/NorskHelsenett/spam/internal/auth"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

const (
	defaultPageSize = 50
	maxPageSize     = 200
)

// EcosystemsListHandler returns distinct ecosystems from both SBOMs and manifests.
func EcosystemsListHandler(db *gorm.DB, authService *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if requireAuth(w, r, authService) == nil {
			return
		}

		// Get ecosystems from both sbom_component_view and manifest_dependencies
		var ecosystems []string
		if err := db.WithContext(r.Context()).Raw(`
			SELECT DISTINCT ecosystem FROM (
				SELECT kind as ecosystem FROM sbom_component_view
				WHERE is_root = false AND kind IS NOT NULL AND kind != ''
				UNION
				SELECT DISTINCT ecosystem FROM manifest_dependencies
				WHERE ecosystem IS NOT NULL AND ecosystem != ''
			) combined
			ORDER BY ecosystem ASC
		`).Pluck("ecosystem", &ecosystems).Error; err != nil {
			http.Error(w, "query failed", http.StatusInternalServerError)
			return
		}

		writeJSON(w, http.StatusOK, map[string][]string{"ecosystems": ecosystems})
	}
}

func parsePagination(r *http.Request) (page, pageSize int) {
	page = 1
	pageSize = defaultPageSize

	if p := r.URL.Query().Get("page"); p != "" {
		if parsed, err := strconv.Atoi(p); err == nil && parsed > 0 {
			page = parsed
		}
	}
	if ps := r.URL.Query().Get("page_size"); ps != "" {
		if parsed, err := strconv.Atoi(ps); err == nil && parsed > 0 && parsed <= maxPageSize {
			pageSize = parsed
		}
	}

	return page, pageSize
}

// isValidUUID checks if the given string is a valid UUID.
func isValidUUID(s string) bool {
	_, err := uuid.Parse(s)
	return err == nil
}
