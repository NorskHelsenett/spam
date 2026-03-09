package uiapi

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/NorskHelsenett/spam/internal/auth"
	"gorm.io/gorm"
)

type AdvancedSearchResult struct {
	Type       string `json:"type"`
	SourceRef  string `json:"source_ref,omitempty"`
	RepoID     string `json:"repo_id"`
	Provider   string `json:"provider"`
	ProviderID string `json:"provider_id,omitempty"`
	BaseURL    string `json:"base_url,omitempty"`
	OwnerPath  string `json:"owner_path,omitempty"`
	Org        string `json:"org"`
	Slug       string `json:"slug"`
	Title      string `json:"title"`
	Value      string `json:"value,omitempty"`
	Snippet    string `json:"snippet,omitempty"`
	CreatedAt  string `json:"created_at,omitempty"`
}

type AdvancedSearchResponse struct {
	Query   string                 `json:"query"`
	Target  string                 `json:"target"`
	Results []AdvancedSearchResult `json:"results"`
	HasMore bool                   `json:"has_more"`
}

type advancedSearchDBRow struct {
	Type       string
	SourceRef  string
	RepoID     string
	Provider   string
	ProviderID string
	BaseURL    string
	OwnerPath  string
	Org        string
	Slug       string
	Title      string
	Value      string
	SourceText string
	CreatedAt  time.Time
}

var advancedSearchTargets = map[string]struct{}{
	"manifest":    {},
	"sbom":        {},
	"secret":      {},
	"contributor": {},
	"language":    {},
	"commit":      {},
	"repo":        {},
	"readme":      {},
}

func normalizeAdvancedTargets(target string) []string {
	target = strings.TrimSpace(strings.ToLower(target))
	if target == "" || target == "all" {
		return []string{"repo", "commit", "language", "contributor", "readme", "manifest", "sbom", "secret"}
	}
	parts := strings.Split(target, ",")
	out := make([]string, 0, len(parts))
	seen := map[string]struct{}{}
	for _, raw := range parts {
		t := strings.TrimSpace(strings.ToLower(raw))
		if t == "" {
			continue
		}
		if _, ok := advancedSearchTargets[t]; !ok {
			continue
		}
		if _, ok := seen[t]; ok {
			continue
		}
		seen[t] = struct{}{}
		out = append(out, t)
	}
	if len(out) == 0 {
		return []string{"repo", "commit", "language", "contributor", "readme", "manifest", "sbom", "secret"}
	}
	return out
}

func compactSnippet(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.ReplaceAll(s, "\t", " ")
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > 240 {
		return s[:240] + "..."
	}
	return s
}

func snippetAround(source, query string) string {
	src := strings.TrimSpace(source)
	q := strings.TrimSpace(query)
	if src == "" {
		return ""
	}
	if q == "" {
		return compactSnippet(src)
	}
	lowerSrc := strings.ToLower(src)
	lowerQ := strings.ToLower(q)
	pos := strings.Index(lowerSrc, lowerQ)
	if pos < 0 {
		return ""
	}
	start := pos - 90
	if start < 0 {
		start = 0
	}
	end := pos + len(q) + 130
	if end > len(src) {
		end = len(src)
	}
	snippet := src[start:end]
	if start > 0 {
		snippet = "..." + snippet
	}
	if end < len(src) {
		snippet += "..."
	}
	return compactSnippet(snippet)
}

func runAdvancedSearchQuery(db *gorm.DB, r *http.Request, query string, perTargetLimit int, target string) ([]advancedSearchDBRow, error) {
	like := "%" + query + "%"
	var rows []advancedSearchDBRow

	switch target {
	case "manifest":
		err := db.WithContext(r.Context()).Raw(`
			SELECT
				'manifest' AS type,
				m.id AS source_ref,
				r.id AS repo_id,
				r.provider,
				COALESCE(pi.id, '') AS provider_id,
				COALESCE(pi.base_url, '') AS base_url,
				COALESCE(pi.owner_path, '') AS owner_path,
				r.org,
				r.slug,
				COALESCE(m.path, m.type, '') AS title,
				COALESCE(m.type, '') AS value,
				CASE
					WHEN strpos(lower(hs.haystack), lower(?)) > 0 THEN
						(CASE WHEN strpos(lower(hs.haystack), lower(?)) > 90 THEN '...' ELSE '' END) ||
						substr(hs.haystack, GREATEST(1, strpos(lower(hs.haystack), lower(?)) - 90), length(?) + 220) ||
						(CASE WHEN strpos(lower(hs.haystack), lower(?)) + length(?) + 130 < length(hs.haystack) THEN '...' ELSE '' END)
					ELSE LEFT(hs.haystack, 240)
				END AS source_text,
				m.created_at
			FROM manifests m
			JOIN repos r ON r.id = m.repo_id
			LEFT JOIN provider_instances pi ON pi.id = r.provider_instance_id AND pi.enabled = true
			CROSS JOIN LATERAL (
				SELECT COALESCE(m.path, '') || E'\n' || COALESCE(m.type, '') || E'\n' || COALESCE(m.content, '') AS haystack
			) hs
			WHERE m.path ILIKE ? OR m.type ILIKE ? OR m.content ILIKE ?
			ORDER BY m.created_at DESC
			LIMIT ?
		`, query, query, query, query, query, query, like, like, like, perTargetLimit).Scan(&rows).Error
		return rows, err
	case "sbom":
		err := db.WithContext(r.Context()).Raw(`
			SELECT
				'sbom' AS type,
				s.id AS source_ref,
				r.id AS repo_id,
				r.provider,
				COALESCE(pi.id, '') AS provider_id,
				COALESCE(pi.base_url, '') AS base_url,
				COALESCE(pi.owner_path, '') AS owner_path,
				r.org,
					r.slug,
					s.format AS title,
					rc.commit_sha AS value,
					LEFT(COALESCE(s.format, '') || E'\n' || COALESCE(convert_from(s.content_bytes, 'utf8'), ''), 60000) AS source_text,
					s.created_at
			FROM sboms s
			JOIN sbom_bindings sb ON sb.sbom_id = s.id AND sb.asset_type = 'REPO_COMMIT'
			JOIN repo_commits rc ON rc.id = sb.asset_ref_id
			JOIN repos r ON r.id = rc.repo_id
			LEFT JOIN provider_instances pi ON pi.id = r.provider_instance_id AND pi.enabled = true
			WHERE s.format ILIKE ? OR convert_from(s.content_bytes, 'utf8') ILIKE ?
			ORDER BY s.created_at DESC
			LIMIT ?
		`, like, like, perTargetLimit).Scan(&rows).Error
		return rows, err
	case "secret":
		err := db.WithContext(r.Context()).Raw(`
			SELECT
				'secret' AS type,
				rs.id AS source_ref,
				r.id AS repo_id,
				r.provider,
				COALESCE(pi.id, '') AS provider_id,
				COALESCE(pi.base_url, '') AS base_url,
				COALESCE(pi.owner_path, '') AS owner_path,
				r.org,
					r.slug,
					'Secret findings' AS title,
					COALESCE(rs.run_id, '') AS value,
					LEFT(COALESCE(rs.findings::text, ''), 60000) AS source_text,
					rs.created_at
			FROM run_secrets rs
			JOIN repos r ON r.id = rs.repo_id
			LEFT JOIN provider_instances pi ON pi.id = r.provider_instance_id AND pi.enabled = true
			WHERE rs.findings::text ILIKE ?
			ORDER BY rs.created_at DESC
			LIMIT ?
		`, like, perTargetLimit).Scan(&rows).Error
		return rows, err
	case "contributor":
		err := db.WithContext(r.Context()).Raw(`
			SELECT
				'contributor' AS type,
				rc.repo_id AS source_ref,
				r.id AS repo_id,
				r.provider,
				COALESCE(pi.id, '') AS provider_id,
				COALESCE(pi.base_url, '') AS base_url,
				COALESCE(pi.owner_path, '') AS owner_path,
				r.org,
					r.slug,
					'Contributors' AS title,
					'' AS value,
					LEFT(COALESCE(rc.contributors_json, ''), 60000) AS source_text,
					rc.synced_at AS created_at
			FROM repo_caches rc
			JOIN repos r ON r.id = rc.repo_id
			LEFT JOIN provider_instances pi ON pi.id = r.provider_instance_id AND pi.enabled = true
			WHERE rc.contributors_json ILIKE ?
			ORDER BY rc.synced_at DESC
			LIMIT ?
		`, like, perTargetLimit).Scan(&rows).Error
		return rows, err
	case "language":
		err := db.WithContext(r.Context()).Raw(`
			SELECT
				'language' AS type,
				rc.repo_id AS source_ref,
				r.id AS repo_id,
				r.provider,
				COALESCE(pi.id, '') AS provider_id,
				COALESCE(pi.base_url, '') AS base_url,
				COALESCE(pi.owner_path, '') AS owner_path,
				r.org,
					r.slug,
					'Languages' AS title,
					'' AS value,
					LEFT(COALESCE(rc.details_json, ''), 60000) AS source_text,
					rc.synced_at AS created_at
			FROM repo_caches rc
			JOIN repos r ON r.id = rc.repo_id
			LEFT JOIN provider_instances pi ON pi.id = r.provider_instance_id AND pi.enabled = true
			WHERE rc.details_json ILIKE ?
			ORDER BY rc.synced_at DESC
			LIMIT ?
		`, like, perTargetLimit).Scan(&rows).Error
		return rows, err
	case "commit":
		err := db.WithContext(r.Context()).Raw(`
			SELECT
				'commit' AS type,
				c.id AS source_ref,
				r.id AS repo_id,
				r.provider,
				COALESCE(pi.id, '') AS provider_id,
				COALESCE(pi.base_url, '') AS base_url,
				COALESCE(pi.owner_path, '') AS owner_path,
				r.org,
					r.slug,
					'Commit' AS title,
					c.commit_sha AS value,
					LEFT(COALESCE(c.commit_sha, '') || E'\n' || COALESCE(c.ref, ''), 60000) AS source_text,
					c.created_at
			FROM repo_commits c
			JOIN repos r ON r.id = c.repo_id
			LEFT JOIN provider_instances pi ON pi.id = r.provider_instance_id AND pi.enabled = true
			WHERE c.commit_sha ILIKE ? OR c.ref ILIKE ?
			ORDER BY c.created_at DESC
			LIMIT ?
		`, like, like, perTargetLimit).Scan(&rows).Error
		return rows, err
	case "repo":
		err := db.WithContext(r.Context()).Raw(`
			SELECT
				'repo' AS type,
				r.id AS source_ref,
				r.id AS repo_id,
				r.provider,
				COALESCE(pi.id, '') AS provider_id,
				COALESCE(pi.base_url, '') AS base_url,
				COALESCE(pi.owner_path, '') AS owner_path,
				r.org,
					r.slug,
					r.org || '/' || r.slug AS title,
					r.provider AS value,
					LEFT((r.org || '/' || r.slug || E'\n' || COALESCE(r.provider, '')), 60000) AS source_text,
					r.created_at
			FROM repos r
			LEFT JOIN provider_instances pi ON pi.id = r.provider_instance_id AND pi.enabled = true
			WHERE r.org ILIKE ? OR r.slug ILIKE ? OR (r.org || '/' || r.slug) ILIKE ?
			ORDER BY r.created_at DESC
			LIMIT ?
		`, like, like, like, perTargetLimit).Scan(&rows).Error
		return rows, err
	case "readme":
		err := db.WithContext(r.Context()).Raw(`
			SELECT
				'readme' AS type,
				rc.repo_id AS source_ref,
				r.id AS repo_id,
				r.provider,
				COALESCE(pi.id, '') AS provider_id,
				COALESCE(pi.base_url, '') AS base_url,
				COALESCE(pi.owner_path, '') AS owner_path,
				r.org,
					r.slug,
					'README' AS title,
					'' AS value,
					LEFT(COALESCE(rc.readme_content, ''), 60000) AS source_text,
					rc.synced_at AS created_at
			FROM repo_caches rc
			JOIN repos r ON r.id = rc.repo_id
			LEFT JOIN provider_instances pi ON pi.id = r.provider_instance_id AND pi.enabled = true
			WHERE rc.readme_content ILIKE ?
			ORDER BY rc.synced_at DESC
			LIMIT ?
		`, like, perTargetLimit).Scan(&rows).Error
		return rows, err
	default:
		return []advancedSearchDBRow{}, nil
	}
}

// AdvancedSearchHandler runs cross-domain searches over repo metadata and artifacts.
// GET /api/search/advanced?q=<query>&target=<all|repo|commit|language|contributor|readme|manifest|sbom|secret>
func AdvancedSearchHandler(db *gorm.DB, authService *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if requireAuth(w, r, authService) == nil {
			return
		}

		q := strings.TrimSpace(r.URL.Query().Get("q"))
		target := strings.TrimSpace(r.URL.Query().Get("target"))

		perPage := 100
		if p, err := strconv.Atoi(r.URL.Query().Get("per_page")); err == nil && p > 0 && p <= 300 {
			perPage = p
		}

		if q == "" {
			writeJSON(w, http.StatusOK, AdvancedSearchResponse{Query: q, Target: target, Results: []AdvancedSearchResult{}, HasMore: false})
			return
		}

		targets := normalizeAdvancedTargets(target)
		perTargetLimit := perPage
		if perTargetLimit < 20 {
			perTargetLimit = 20
		}

		results := make([]AdvancedSearchResult, 0, perPage)
		seen := map[string]struct{}{}

		for _, t := range targets {
			rows, err := runAdvancedSearchQuery(db, r, q, perTargetLimit, t)
			if err != nil {
				http.Error(w, "search failed", http.StatusInternalServerError)
				return
			}
			for _, row := range rows {
				key := row.Type + "|" + row.RepoID + "|" + row.Title + "|" + row.Value
				if _, ok := seen[key]; ok {
					continue
				}
				seen[key] = struct{}{}
				snippet := snippetAround(row.SourceText, q)
				if snippet == "" {
					snippet = snippetAround(row.Title+" "+row.Value, q)
				}
				results = append(results, AdvancedSearchResult{
					Type:       row.Type,
					SourceRef:  row.SourceRef,
					RepoID:     row.RepoID,
					Provider:   row.Provider,
					ProviderID: row.ProviderID,
					BaseURL:    row.BaseURL,
					OwnerPath:  row.OwnerPath,
					Org:        row.Org,
					Slug:       row.Slug,
					Title:      row.Title,
					Value:      row.Value,
					Snippet:    snippet,
					CreatedAt:  row.CreatedAt.UTC().Format(time.RFC3339),
				})
			}
		}

		hasMore := len(results) > perPage
		if hasMore {
			results = results[:perPage]
		}

		writeJSON(w, http.StatusOK, AdvancedSearchResponse{
			Query:   q,
			Target:  target,
			Results: results,
			HasMore: hasMore,
		})
	}
}

type AdvancedSearchPreviewResponse struct {
	Type      string            `json:"type"`
	Raw       string            `json:"raw"`
	Metadata  map[string]string `json:"metadata"`
	RepoID    string            `json:"repo_id,omitempty"`
	Provider  string            `json:"provider,omitempty"`
	Org       string            `json:"org,omitempty"`
	Slug      string            `json:"slug,omitempty"`
	SourceRef string            `json:"source_ref,omitempty"`
}

// AdvancedSearchPreviewHandler returns raw source content plus metadata for a search hit.
// GET /api/search/preview?type=<type>&source_ref=<id>&repo_id=<repo_id>
func AdvancedSearchPreviewHandler(db *gorm.DB, authService *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if requireAuth(w, r, authService) == nil {
			return
		}

		targetType := strings.TrimSpace(strings.ToLower(r.URL.Query().Get("type")))
		sourceRef := strings.TrimSpace(r.URL.Query().Get("source_ref"))
		repoID := strings.TrimSpace(r.URL.Query().Get("repo_id"))

		if targetType == "" || sourceRef == "" {
			http.Error(w, "type and source_ref required", http.StatusBadRequest)
			return
		}
		if _, ok := advancedSearchTargets[targetType]; !ok {
			http.Error(w, "unsupported type", http.StatusBadRequest)
			return
		}

		resp := AdvancedSearchPreviewResponse{
			Type:      targetType,
			SourceRef: sourceRef,
			Metadata:  map[string]string{},
		}

		switch targetType {
		case "manifest":
			var row struct {
				ID       string
				RepoID   string
				Path     string
				Type     string
				Content  string
				Metadata string
				Provider string
				Org      string
				Slug     string
			}
			err := db.WithContext(r.Context()).Raw(`
				SELECT
					m.id,
					m.repo_id,
					m.path,
					m.type,
					COALESCE(m.content, '') AS content,
					COALESCE(m.metadata::text, '{}') AS metadata,
					r.provider,
					r.org,
					r.slug
				FROM manifests m
				JOIN repos r ON r.id = m.repo_id
				WHERE m.id = ?
				LIMIT 1
			`, sourceRef).Scan(&row).Error
			if err != nil || row.ID == "" {
				http.Error(w, "preview not found", http.StatusNotFound)
				return
			}
			resp.RepoID, resp.Provider, resp.Org, resp.Slug = row.RepoID, row.Provider, row.Org, row.Slug
			resp.Raw = row.Content
			resp.Metadata["path"] = row.Path
			resp.Metadata["manifest_type"] = row.Type
			resp.Metadata["manifest_id"] = row.ID
			resp.Metadata["manifest_metadata_json"] = row.Metadata
		case "sbom":
			var row struct {
				ID        string
				Format    string
				Raw       string
				RepoID    string
				Provider  string
				Org       string
				Slug      string
				CommitSHA string
			}
			err := db.WithContext(r.Context()).Raw(`
				SELECT
					s.id,
					s.format,
					COALESCE(convert_from(s.content_bytes, 'utf8'), '') AS raw,
					r.id AS repo_id,
					r.provider,
					r.org,
					r.slug,
					COALESCE(rc.commit_sha, '') AS commit_sha
				FROM sboms s
				JOIN sbom_bindings sb ON sb.sbom_id = s.id AND sb.asset_type = 'REPO_COMMIT'
				JOIN repo_commits rc ON rc.id = sb.asset_ref_id
				JOIN repos r ON r.id = rc.repo_id
				WHERE s.id = ?
				LIMIT 1
			`, sourceRef).Scan(&row).Error
			if err != nil || row.ID == "" {
				http.Error(w, "preview not found", http.StatusNotFound)
				return
			}
			resp.RepoID, resp.Provider, resp.Org, resp.Slug = row.RepoID, row.Provider, row.Org, row.Slug
			resp.Raw = row.Raw
			resp.Metadata["sbom_id"] = row.ID
			resp.Metadata["format"] = row.Format
			if row.CommitSHA != "" {
				resp.Metadata["commit_sha"] = row.CommitSHA
			}
		case "secret":
			var row struct {
				ID           string
				RepoID       string
				Provider     string
				Org          string
				Slug         string
				RunID        string
				FindingCount int
				Raw          string
			}
			err := db.WithContext(r.Context()).Raw(`
				SELECT
					rs.id,
					rs.repo_id,
					r.provider,
					r.org,
					r.slug,
					rs.run_id,
					rs.finding_count,
					COALESCE(rs.findings::text, '') AS raw
				FROM run_secrets rs
				JOIN repos r ON r.id = rs.repo_id
				WHERE rs.id = ?
				LIMIT 1
			`, sourceRef).Scan(&row).Error
			if err != nil || row.ID == "" {
				http.Error(w, "preview not found", http.StatusNotFound)
				return
			}
			resp.RepoID, resp.Provider, resp.Org, resp.Slug = row.RepoID, row.Provider, row.Org, row.Slug
			resp.Raw = row.Raw
			resp.Metadata["run_id"] = row.RunID
			resp.Metadata["finding_count"] = strconv.Itoa(row.FindingCount)
			resp.Metadata["secret_id"] = row.ID
		case "contributor", "language", "readme":
			var row struct {
				RepoID           string
				Provider         string
				Org              string
				Slug             string
				ReadmeContent    string
				ContributorsJSON string
				DetailsJSON      string
			}
			err := db.WithContext(r.Context()).Raw(`
				SELECT
					rc.repo_id,
					r.provider,
					r.org,
					r.slug,
					COALESCE(rc.readme_content, '') AS readme_content,
					COALESCE(rc.contributors_json, '') AS contributors_json,
					COALESCE(rc.details_json, '') AS details_json
				FROM repo_caches rc
				JOIN repos r ON r.id = rc.repo_id
				WHERE rc.repo_id = ?
				LIMIT 1
			`, sourceRef).Scan(&row).Error
			if err != nil || row.RepoID == "" {
				http.Error(w, "preview not found", http.StatusNotFound)
				return
			}
			resp.RepoID, resp.Provider, resp.Org, resp.Slug = row.RepoID, row.Provider, row.Org, row.Slug
			if targetType == "contributor" {
				resp.Raw = row.ContributorsJSON
				resp.Metadata["source"] = "repo_caches.contributors_json"
			} else if targetType == "language" {
				resp.Raw = row.DetailsJSON
				resp.Metadata["source"] = "repo_caches.details_json"
			} else {
				resp.Raw = row.ReadmeContent
				resp.Metadata["source"] = "repo_caches.readme_content"
			}
		case "commit":
			var row struct {
				ID        string
				RepoID    string
				Provider  string
				Org       string
				Slug      string
				CommitSHA string
				Ref       string
				Raw       string
			}
			err := db.WithContext(r.Context()).Raw(`
				SELECT
					c.id,
					c.repo_id,
					r.provider,
					r.org,
					r.slug,
					COALESCE(c.commit_sha, '') AS commit_sha,
					COALESCE(c.ref, '') AS ref,
					(COALESCE(c.commit_sha, '') || E'\n' || COALESCE(c.ref, '')) AS raw
				FROM repo_commits c
				JOIN repos r ON r.id = c.repo_id
				WHERE c.id = ?
				LIMIT 1
			`, sourceRef).Scan(&row).Error
			if err != nil || row.ID == "" {
				http.Error(w, "preview not found", http.StatusNotFound)
				return
			}
			resp.RepoID, resp.Provider, resp.Org, resp.Slug = row.RepoID, row.Provider, row.Org, row.Slug
			resp.Raw = row.Raw
			resp.Metadata["commit_sha"] = row.CommitSHA
			if row.Ref != "" {
				resp.Metadata["ref"] = row.Ref
			}
		case "repo":
			var row struct {
				ID       string
				Provider string
				Org      string
				Slug     string
				Details  string
				Readme   string
				Commits  string
				Contribs string
			}
			err := db.WithContext(r.Context()).Raw(`
				SELECT
					r.id,
					r.provider,
					r.org,
					r.slug,
					COALESCE(rc.details_json, '') AS details,
					COALESCE(rc.readme_content, '') AS readme,
					COALESCE(rc.commits_json, '') AS commits,
					COALESCE(rc.contributors_json, '') AS contribs
				FROM repos r
				LEFT JOIN repo_caches rc ON rc.repo_id = r.id
				WHERE r.id = ?
				LIMIT 1
			`, sourceRef).Scan(&row).Error
			if err != nil || row.ID == "" {
				http.Error(w, "preview not found", http.StatusNotFound)
				return
			}
			resp.RepoID, resp.Provider, resp.Org, resp.Slug = row.ID, row.Provider, row.Org, row.Slug
			resp.Raw = strings.TrimSpace(row.Details + "\n\n" + row.Readme + "\n\n" + row.Commits + "\n\n" + row.Contribs)
			resp.Metadata["repo"] = row.Org + "/" + row.Slug
			resp.Metadata["provider"] = row.Provider
		}

		if repoID != "" && resp.RepoID != "" && repoID != resp.RepoID {
			http.Error(w, "preview mismatch", http.StatusBadRequest)
			return
		}
		if len(resp.Raw) > 250000 {
			resp.Raw = resp.Raw[:250000] + "\n...truncated..."
		}

		writeJSON(w, http.StatusOK, resp)
	}
}
