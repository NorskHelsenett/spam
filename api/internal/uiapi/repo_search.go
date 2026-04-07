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
	OwnerPath  string  `json:"owner_path,omitempty"`
}

type RepoSearchResponse struct {
	Query   string             `json:"query"`
	Results []RepoSearchResult `json:"results"`
	HasMore bool               `json:"has_more"`
	Offset  int                `json:"offset"`
}

// RepoSearchHandler searches repos by org and slug.
// GET /api/repos/search?q=<query>&limit=20
//
// Results are ranked in explicit buckets first so exact and word-start matches
// sort ahead of looser substring and fuzzy matches. This also includes
// initialism-style matches such as "ilm" for "image-link-manager".
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
		if l, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && l > 0 && l <= 200 {
			limit = l
		}

		offset := 0
		if o, err := strconv.Atoi(r.URL.Query().Get("offset")); err == nil && o > 0 {
			offset = o
		}

		providerID := r.URL.Query().Get("provider_id")

		var rows []RepoSearchResult
		err := db.WithContext(r.Context()).Raw(`
			SELECT
				r.id,
				r.provider,
				r.org,
				r.slug,
				GREATEST(
					word_similarity(LOWER(?), LOWER(r.slug)),
					word_similarity(LOWER(?), LOWER(r.org)),
					word_similarity(LOWER(?), LOWER(r.org || '/' || r.slug))
				) AS score,
				COALESCE(pi.id, '')         AS provider_id,
				COALESCE(pi.base_url, '')   AS base_url,
				COALESCE(pi.owner_path, '') AS owner_path
			FROM repos r
			LEFT JOIN provider_instances pi ON pi.id = r.provider_instance_id AND pi.enabled = true
			WHERE (
				r.slug ILIKE '%' || ? || '%'
				OR r.org ILIKE '%' || ? || '%'
				OR (r.org || '/' || r.slug) ILIKE '%' || ? || '%'
				OR LOWER(?) <% LOWER(r.slug)
				OR LOWER(?) <% LOWER(r.org)
				OR LOWER(?) <% LOWER(r.org || '/' || r.slug)
				OR (
					SELECT COALESCE(string_agg(LEFT(word, 1), ''), '')
					FROM regexp_split_to_table(
						regexp_replace(LOWER(r.org || ' ' || r.slug), '[^a-z0-9]+', ' ', 'g'),
						' +'
					) AS word
					WHERE word <> ''
				) LIKE LOWER(?) || '%'
			)
			AND pi.id IS NOT NULL
			AND (? = '' OR pi.id = ?)
			ORDER BY
				CASE
					WHEN LOWER(r.slug) = LOWER(?) THEN 0
					WHEN LOWER(r.org || '/' || r.slug) = LOWER(?) THEN 1
					WHEN EXISTS (
						SELECT 1
						FROM regexp_split_to_table(
							regexp_replace(LOWER(r.slug), '[^a-z0-9]+', ' ', 'g'),
							' +'
						) AS word
						WHERE word <> '' AND word = LOWER(?)
					) THEN 2
					WHEN EXISTS (
						SELECT 1
						FROM regexp_split_to_table(
							regexp_replace(LOWER(r.org || ' ' || r.slug), '[^a-z0-9]+', ' ', 'g'),
							' +'
						) AS word
						WHERE word <> '' AND word = LOWER(?)
					) THEN 3
					WHEN LOWER(r.slug) LIKE LOWER(?) || '%' THEN 4
					WHEN LOWER(r.org || '/' || r.slug) LIKE LOWER(?) || '%' THEN 5
					WHEN EXISTS (
						SELECT 1
						FROM regexp_split_to_table(
							regexp_replace(LOWER(r.org || ' ' || r.slug), '[^a-z0-9]+', ' ', 'g'),
							' +'
						) AS word
						WHERE word <> '' AND word LIKE LOWER(?) || '%'
					) THEN 6
					WHEN (
						SELECT COALESCE(string_agg(LEFT(word, 1), ''), '')
						FROM regexp_split_to_table(
							regexp_replace(LOWER(r.org || ' ' || r.slug), '[^a-z0-9]+', ' ', 'g'),
							' +'
						) AS word
						WHERE word <> ''
					) LIKE LOWER(?) || '%' THEN 7
					WHEN LOWER(r.slug) ILIKE '%' || LOWER(?) || '%' THEN 8
					WHEN LOWER(r.org || '/' || r.slug) ILIKE '%' || LOWER(?) || '%' THEN 9
					ELSE 10
				END ASC,
				score DESC,
				LOWER(r.org) ASC,
				LOWER(r.slug) ASC
			LIMIT ? OFFSET ?
			`,
			q, q, q,
			q, q, q, q, q, q, q,
			providerID, providerID,
			q, q, q, q, q, q, q, q, q, q,
			limit+1, offset,
		).Scan(&rows).Error
		if err != nil {
			http.Error(w, "search failed", http.StatusInternalServerError)
			return
		}

		if rows == nil {
			rows = []RepoSearchResult{}
		}

		hasMore := len(rows) > limit
		if hasMore {
			rows = rows[:limit]
		}

		writeJSON(w, http.StatusOK, RepoSearchResponse{
			Query:   q,
			Results: rows,
			HasMore: hasMore,
			Offset:  offset,
		})
	}
}
