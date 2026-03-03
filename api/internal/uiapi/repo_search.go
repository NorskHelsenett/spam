package uiapi

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/NorskHelsenett/spam/internal/auth"
	"gorm.io/gorm"
)

type RepoSearchResult struct {
	ID         string  `json:"id"`
	Provider   string  `json:"provider"`
	Org        string  `json:"org"`
	Slug       string  `json:"slug"`
	Score      float64 `json:"score"`
	ProviderID string  `json:"provider_id,omitempty"`
	BaseURL    string  `json:"base_url,omitempty"`
}

type RepoSearchResponse struct {
	Query   string             `json:"query"`
	Results []RepoSearchResult `json:"results"`
}

// RepoSearchHandler performs fuzzy search over repos by slug and org name.
// GET /api/repos/search?q=<query>&limit=20
//
// Results are ranked by word_similarity so partial names ("spam", "norsk")
// score higher than unrelated repos. Both ILIKE (exact substring) and the
// trigram <% operator (fuzzy) are used so that near-matches surface too.
func RepoSearchHandler(db *gorm.DB, authService *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if requireAuth(w, r, authService) == nil {
			return
		}

		q := strings.TrimSpace(r.URL.Query().Get("q"))
		if q == "" {
			http.Error(w, "q required", http.StatusBadRequest)
			return
		}

		limit := 20
		if l, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && l > 0 && l <= 100 {
			limit = l
		}

		var rows []RepoSearchResult
		err := db.WithContext(r.Context()).Raw(`
			SELECT
				r.id,
				r.provider,
				r.org,
				r.slug,
				GREATEST(
					word_similarity(?, r.slug),
					word_similarity(?, r.org)
				) AS score,
				COALESCE(pi.id, '')       AS provider_id,
				COALESCE(pi.base_url, '') AS base_url
			FROM repos r
			LEFT JOIN LATERAL (
				SELECT pi.id, pi.base_url
				FROM provider_instances pi
				WHERE pi.type = r.provider
				  AND pi.enabled = true
				  AND (
				    pi.owner_path = ''
				    OR r.org = pi.owner_path
				    OR r.org LIKE pi.owner_path || '/%'
				  )
				ORDER BY
					CASE WHEN pi.owner_path != '' THEN 0 ELSE 1 END,
					pi.created_at
				LIMIT 1
			) pi ON true
			WHERE (
				r.slug ILIKE '%' || ? || '%'
				OR r.org  ILIKE '%' || ? || '%'
				OR ? <% r.slug
				OR ? <% r.org
			)
			AND pi.id IS NOT NULL
			ORDER BY score DESC, r.org ASC, r.slug ASC
			LIMIT ?
		`, q, q, q, q, q, q, limit).Scan(&rows).Error
		if err != nil {
			http.Error(w, "search failed", http.StatusInternalServerError)
			return
		}

		if rows == nil {
			rows = []RepoSearchResult{}
		}

		writeJSON(w, http.StatusOK, RepoSearchResponse{
			Query:   q,
			Results: rows,
		})
	}
}
