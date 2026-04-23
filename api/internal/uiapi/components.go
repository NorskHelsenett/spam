package uiapi

import (
	"net/http"
	"strconv"
	"time"

	"github.com/NorskHelsenett/spam/internal/auth"
	"github.com/NorskHelsenett/spam/internal/cache"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

const (
	defaultPageSize = 50
	maxPageSize     = 200

	ecosystemsCacheKey = "components:ecosystems"
	ecosystemsCacheTTL = 15 * time.Minute
)

type ecosystemsResponse struct {
	Ecosystems []string `json:"ecosystems"`
}

// EcosystemsListHandler returns distinct ecosystems from both SBOMs and manifests.
// The result set changes only when new SBOMs/manifests are ingested, so it is
// cached in kv_store for ecosystemsCacheTTL.
func EcosystemsListHandler(db *gorm.DB, authService *auth.Service, c cache.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if requireAuth(w, r, authService) == nil {
			return
		}

		if cached, ok, _ := cache.GetJSON[ecosystemsResponse](r.Context(), c, ecosystemsCacheKey); ok {
			writeJSON(w, http.StatusOK, cached)
			return
		}

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

		resp := ecosystemsResponse{Ecosystems: ecosystems}
		_ = cache.SetJSON(r.Context(), c, ecosystemsCacheKey, resp, ecosystemsCacheTTL)
		writeJSON(w, http.StatusOK, resp)
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
