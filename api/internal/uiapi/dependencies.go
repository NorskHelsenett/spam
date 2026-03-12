package uiapi

import (
	"context"
	"database/sql"
	"encoding/csv"
	"encoding/json"
	"log"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/NorskHelsenett/spam/internal/auth"
	"gorm.io/gorm"
)

// UnifiedDependency combines data from SBOMs and manifests
type UnifiedDependency struct {
	Name         string   `json:"name"`
	Ecosystem    string   `json:"ecosystem"`
	PURL         string   `json:"purl,omitempty"`   // PURL without version
	Sources      []string `json:"sources"`          // ["sbom", "manifest", "both"]
	VersionCount int      `json:"version_count"`    // How many different versions
	SBOMCount    int      `json:"sbom_count"`       // How many SBOMs contain this
	RepoCount    int      `json:"repo_count"`       // How many repos use this
	HasDirect    bool     `json:"has_direct"`       // At least one version is direct
	Scopes       []string `json:"scopes,omitempty"` // All unique scopes across versions
}

// DependencyExportCSVHandler exports expanded dependency rows for forensics.
// Each row represents a repo+component+version tuple merged from SBOM and manifest sources.
func DependencyExportCSVHandler(db *gorm.DB, authService *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if requireAuth(w, r, authService) == nil {
			return
		}

		search := r.URL.Query().Get("q")
		ecosystem := r.URL.Query().Get("ecosystem")
		repoID := r.URL.Query().Get("repo_id")
		source := r.URL.Query().Get("source") // "", "sbom", "manifest", "both"
		parsedSearch, err := parseDependencySearchQuery(search)
		if err != nil {
			http.Error(w, "invalid dependency search query: "+err.Error(), http.StatusBadRequest)
			return
		}

		query := `
			WITH sbom_rows AS (
				SELECT DISTINCT
					r.id as repo_id,
					r.provider,
					r.org,
					r.slug,
					COALESCE(s.version, NULLIF(s.purl_version, ''), '') as version,
					NULLIF(s.purl, '') as component_purl,
					COALESCE(s.package_name, s.normalized_name, s.name) as component_name,
					s.kind as ecosystem
				FROM sbom_component_view s
				JOIN repo_commits rc ON rc.id = s.asset_ref_id
				JOIN repos r ON r.id = rc.repo_id
				WHERE s.is_root = false
				  AND s.purl IS NOT NULL
				  AND s.asset_type = 'REPO_COMMIT'
				  AND COALESCE(s.package_name, s.normalized_name, s.name) IS NOT NULL
			),
			manifest_rows AS (
				SELECT DISTINCT
					r.id as repo_id,
					r.provider,
					r.org,
					r.slug,
					COALESCE(md.version, '') as version,
					NULL::text as component_purl,
					md.name as component_name,
					md.ecosystem as ecosystem
				FROM manifest_dependencies md
				JOIN manifests m ON m.id = md.manifest_id
				JOIN repos r ON r.id = m.repo_id
				WHERE md.name IS NOT NULL
			),
			merged AS (
				SELECT
					COALESCE(s.repo_id, m.repo_id) as repo_id,
					COALESCE(s.provider, m.provider) as provider,
					COALESCE(s.org, m.org) as org,
					COALESCE(s.slug, m.slug) as slug,
					COALESCE(s.version, m.version) as version,
					COALESCE(s.component_purl, m.component_purl, '') as component_purl,
					COALESCE(s.component_name, m.component_name) as component_name,
					COALESCE(s.ecosystem, m.ecosystem) as ecosystem,
					(s.repo_id IS NOT NULL) as has_sbom,
					(m.repo_id IS NOT NULL) as has_manifest
				FROM sbom_rows s
				FULL OUTER JOIN manifest_rows m
					ON s.repo_id = m.repo_id
					AND s.component_name = m.component_name
					AND s.ecosystem = m.ecosystem
					AND s.version = m.version
			)
			SELECT DISTINCT
				concat_ws('/', merged.provider, merged.org, merged.slug) as repo,
				merged.version,
				merged.component_purl,
				merged.component_name,
				merged.ecosystem,
				('/app/providers/repo?provider=' || merged.provider || '&path=' || merged.org || '/' || merged.slug
					|| CASE WHEN COALESCE(pi.base_url, '') <> '' THEN '&base_url=' || pi.base_url ELSE '' END
				) AS spam_url
			FROM merged
			LEFT JOIN repos r ON r.id = merged.repo_id
			LEFT JOIN provider_instances pi ON pi.id = r.provider_instance_id
			WHERE 1=1
		`

		args := []interface{}{}
		if parsedSearch.Structured {
			predicate, predicateArgs := buildStructuredDependencyPredicate("component_name", "version", parsedSearch.Groups)
			if predicate != "" {
				query += ` AND ` + predicate
				args = append(args, predicateArgs...)
			}
		} else if search != "" {
			query += ` AND (component_name ILIKE ? OR component_purl ILIKE ?)`
			args = append(args, "%"+search+"%", "%"+search+"%")
		}
		if ecosystem != "" {
			query += ` AND ecosystem = ?`
			args = append(args, ecosystem)
		}
		if repoID != "" {
			query += ` AND repo_id = ?`
			args = append(args, repoID)
		}

		switch source {
		case "sbom":
			query += ` AND has_sbom = true AND has_manifest = false`
		case "manifest":
			query += ` AND has_sbom = false AND has_manifest = true`
		case "both":
			query += ` AND has_sbom = true AND has_manifest = true`
		}

		query += ` ORDER BY repo ASC, component_name ASC, version ASC`

		rows, err := db.WithContext(r.Context()).Raw(query, args...).Rows()
		if err != nil {
			log.Printf("dependency export query error: %v", err)
			http.Error(w, "database error", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		filename := "dependencies-forensics-" + time.Now().Format("2006-01-02") + ".csv"
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)

		cw := csv.NewWriter(w)
		if err := cw.Write([]string{"repo", "version", "component_purl", "component_name", "ecosystem", "spam_url"}); err != nil {
			log.Printf("dependency export header write error: %v", err)
			http.Error(w, "csv write error", http.StatusInternalServerError)
			return
		}

		spamBaseURL := requestBaseURL(r)

		for rows.Next() {
			var repo, version, purl, name, eco, spamURL sql.NullString
			if err := rows.Scan(&repo, &version, &purl, &name, &eco, &spamURL); err != nil {
				log.Printf("dependency export scan error: %v", err)
				continue
			}
			spamURLValue := spamURL.String
			if spamBaseURL != "" && strings.HasPrefix(spamURLValue, "/") {
				spamURLValue = spamBaseURL + spamURLValue
			}
			record := []string{
				repo.String,
				version.String,
				purl.String,
				name.String,
				eco.String,
				spamURLValue,
			}
			if err := cw.Write(record); err != nil {
				log.Printf("dependency export row write error: %v", err)
				http.Error(w, "csv write error", http.StatusInternalServerError)
				return
			}
		}

		cw.Flush()
		if err := cw.Error(); err != nil {
			log.Printf("dependency export flush error: %v", err)
			http.Error(w, "csv write error", http.StatusInternalServerError)
			return
		}
	}
}

// DependencyExportFullCSVHandler exports expanded dependency rows plus URLs and contributor emails.
func DependencyExportFullCSVHandler(db *gorm.DB, authService *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if requireAuth(w, r, authService) == nil {
			return
		}

		search := r.URL.Query().Get("q")
		ecosystem := r.URL.Query().Get("ecosystem")
		repoID := r.URL.Query().Get("repo_id")
		source := r.URL.Query().Get("source")
		parsedSearch, err := parseDependencySearchQuery(search)
		if err != nil {
			http.Error(w, "invalid dependency search query: "+err.Error(), http.StatusBadRequest)
			return
		}

		query := `
			WITH sbom_rows AS (
				SELECT DISTINCT
					r.id as repo_id,
					r.provider,
					r.org,
					r.slug,
					COALESCE(s.version, NULLIF(s.purl_version, ''), '') as version,
					NULLIF(s.purl, '') as component_purl,
					COALESCE(s.package_name, s.normalized_name, s.name) as component_name,
					s.kind as ecosystem
				FROM sbom_component_view s
				JOIN repo_commits rc ON rc.id = s.asset_ref_id
				JOIN repos r ON r.id = rc.repo_id
				WHERE s.is_root = false
				  AND s.purl IS NOT NULL
				  AND s.asset_type = 'REPO_COMMIT'
				  AND COALESCE(s.package_name, s.normalized_name, s.name) IS NOT NULL
			),
			manifest_rows AS (
				SELECT DISTINCT
					r.id as repo_id,
					r.provider,
					r.org,
					r.slug,
					COALESCE(md.version, '') as version,
					NULL::text as component_purl,
					md.name as component_name,
					md.ecosystem as ecosystem
				FROM manifest_dependencies md
				JOIN manifests m ON m.id = md.manifest_id
				JOIN repos r ON r.id = m.repo_id
				WHERE md.name IS NOT NULL
			),
			merged AS (
				SELECT
					COALESCE(s.repo_id, m.repo_id) as repo_id,
					COALESCE(s.provider, m.provider) as provider,
					COALESCE(s.org, m.org) as org,
					COALESCE(s.slug, m.slug) as slug,
					COALESCE(s.version, m.version) as version,
					COALESCE(s.component_purl, m.component_purl, '') as component_purl,
					COALESCE(s.component_name, m.component_name) as component_name,
					COALESCE(s.ecosystem, m.ecosystem) as ecosystem,
					(s.repo_id IS NOT NULL) as has_sbom,
					(m.repo_id IS NOT NULL) as has_manifest
				FROM sbom_rows s
				FULL OUTER JOIN manifest_rows m
					ON s.repo_id = m.repo_id
					AND s.component_name = m.component_name
					AND s.ecosystem = m.ecosystem
					AND s.version = m.version
			)
			SELECT DISTINCT
				merged.repo_id,
				concat_ws('/', merged.provider, merged.org, merged.slug) as repo,
				merged.version,
				merged.component_purl,
				merged.component_name,
				merged.ecosystem,
				merged.provider,
				merged.org,
				merged.slug,
				COALESCE(pi.base_url, '') as provider_base_url
			FROM merged
			LEFT JOIN repos r ON r.id = merged.repo_id
			LEFT JOIN provider_instances pi ON pi.id = r.provider_instance_id
			WHERE 1=1
		`

		args := []interface{}{}
		if parsedSearch.Structured {
			predicate, predicateArgs := buildStructuredDependencyPredicate("merged.component_name", "merged.version", parsedSearch.Groups)
			if predicate != "" {
				query += ` AND ` + predicate
				args = append(args, predicateArgs...)
			}
		} else if search != "" {
			query += ` AND (merged.component_name ILIKE ? OR merged.component_purl ILIKE ?)`
			args = append(args, "%"+search+"%", "%"+search+"%")
		}
		if ecosystem != "" {
			query += ` AND merged.ecosystem = ?`
			args = append(args, ecosystem)
		}
		if repoID != "" {
			query += ` AND merged.repo_id = ?`
			args = append(args, repoID)
		}
		switch source {
		case "sbom":
			query += ` AND merged.has_sbom = true AND merged.has_manifest = false`
		case "manifest":
			query += ` AND merged.has_sbom = false AND merged.has_manifest = true`
		case "both":
			query += ` AND merged.has_sbom = true AND merged.has_manifest = true`
		}

		query += ` ORDER BY repo ASC, merged.component_name ASC, merged.version ASC`

		rows, err := db.WithContext(r.Context()).Raw(query, args...).Rows()
		if err != nil {
			log.Printf("dependency full export query error: %v", err)
			http.Error(w, "database error", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		filename := "dependencies-full-" + time.Now().Format("2006-01-02") + ".csv"
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)

		cw := csv.NewWriter(w)
		if err := cw.Write([]string{"repo", "version", "component_purl", "component_name", "ecosystem", "repo_url", "spam_url", "contributor_emails"}); err != nil {
			http.Error(w, "csv write error", http.StatusInternalServerError)
			return
		}

		type exportRow struct {
			RepoID          string
			Repo            string
			Version         string
			Purl            string
			Name            string
			Eco             string
			Provider        string
			Org             string
			Slug            string
			ProviderBaseURL string
		}
		collected := make([]exportRow, 0, 1024)
		repoIDs := make([]string, 0, 512)
		seenRepoIDs := map[string]struct{}{}
		for rows.Next() {
			var repoID, repo, version, purl, name, eco, provider, org, slug, providerBaseURL sql.NullString
			if err := rows.Scan(&repoID, &repo, &version, &purl, &name, &eco, &provider, &org, &slug, &providerBaseURL); err != nil {
				log.Printf("dependency full export scan error: %v", err)
				continue
			}
			row := exportRow{
				RepoID:          repoID.String,
				Repo:            repo.String,
				Version:         version.String,
				Purl:            purl.String,
				Name:            name.String,
				Eco:             eco.String,
				Provider:        provider.String,
				Org:             org.String,
				Slug:            slug.String,
				ProviderBaseURL: providerBaseURL.String,
			}
			collected = append(collected, row)
			if row.RepoID != "" {
				if _, ok := seenRepoIDs[row.RepoID]; !ok {
					seenRepoIDs[row.RepoID] = struct{}{}
					repoIDs = append(repoIDs, row.RepoID)
				}
			}
		}
		contributorEmailsByRepo := loadContributorEmailsByRepo(db, r.Context(), repoIDs)
		spamBaseURL := requestBaseURL(r)
		for _, row := range collected {
			providerType := inferProviderType(row.Provider, row.ProviderBaseURL)
			repoURL := buildProviderRepoURL(providerType, row.ProviderBaseURL, row.Org, row.Slug)
			spamURL := buildSpamRepoURL(spamBaseURL, providerType, row.Org, row.Slug, row.ProviderBaseURL)
			record := []string{row.Repo, row.Version, row.Purl, row.Name, row.Eco, repoURL, spamURL, contributorEmailsByRepo[row.RepoID]}
			if err := cw.Write(record); err != nil {
				http.Error(w, "csv write error", http.StatusInternalServerError)
				return
			}
		}
		cw.Flush()
		if err := cw.Error(); err != nil {
			http.Error(w, "csv write error", http.StatusInternalServerError)
			return
		}
	}
}

// DependencyDetailExportCSVHandler exports a single dependency's repo usage as CSV.
func DependencyDetailExportCSVHandler(db *gorm.DB, authService *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if requireAuth(w, r, authService) == nil {
			return
		}

		name := r.URL.Query().Get("name")
		ecosystem := r.URL.Query().Get("ecosystem")
		versions := parseVersionFilters(r)
		source := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("source")))
		if name == "" || ecosystem == "" {
			http.Error(w, "name and ecosystem required", http.StatusBadRequest)
			return
		}
		if source != "" && source != "sbom" && source != "manifest" && source != "both" {
			http.Error(w, "invalid source", http.StatusBadRequest)
			return
		}
		if source == "both" {
			source = ""
		}

		assets, err := queryDependencyAssetsForExport(db, r.Context(), name, ecosystem, versions, source)
		if err != nil {
			log.Printf("dependency detail export query error: %v", err)
			http.Error(w, "database error", http.StatusInternalServerError)
			return
		}

		repoIDs := make([]string, 0, len(assets))
		seen := map[string]struct{}{}
		for _, a := range assets {
			if a.RepoID == "" {
				continue
			}
			if _, ok := seen[a.RepoID]; ok {
				continue
			}
			seen[a.RepoID] = struct{}{}
			repoIDs = append(repoIDs, a.RepoID)
		}
		contributorEmailsByRepo := loadContributorEmailsByRepo(db, r.Context(), repoIDs)

		filename := strings.ReplaceAll(name, "/", "_") + "-" + ecosystem + "-details.csv"
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
		cw := csv.NewWriter(w)
		if err := cw.Write([]string{"package", "ecosystem", "version", "type", "repository", "source", "repo_url", "spam_url", "contributor_emails"}); err != nil {
			http.Error(w, "csv write error", http.StatusInternalServerError)
			return
		}

		spamBaseURL := requestBaseURL(r)
		for _, a := range assets {
			repository := ""
			assetType := "repo"
			if a.AssetType == "IMAGE_DIGEST" {
				assetType = "image"
			} else {
				repository = strings.Trim(strings.TrimSpace(a.Org)+"/"+strings.TrimSpace(a.Slug), "/")
			}
			providerType := inferProviderType(a.Provider, a.ProviderBaseURL)
			repoURL := buildProviderRepoURL(providerType, a.ProviderBaseURL, a.Org, a.Slug)
			spamURL := buildSpamRepoURL(spamBaseURL, providerType, a.Org, a.Slug, a.ProviderBaseURL)
			record := []string{
				name,
				ecosystem,
				a.Version,
				assetType,
				repository,
				a.Source,
				repoURL,
				spamURL,
				contributorEmailsByRepo[a.RepoID],
			}
			if err := cw.Write(record); err != nil {
				http.Error(w, "csv write error", http.StatusInternalServerError)
				return
			}
		}
		cw.Flush()
		if err := cw.Error(); err != nil {
			http.Error(w, "csv write error", http.StatusInternalServerError)
			return
		}
	}
}

func requestBaseURL(r *http.Request) string {
	base := strings.TrimRight(strings.TrimSpace(r.Header.Get("Origin")), "/")
	if base != "" {
		return base
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if xfProto := strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")); xfProto != "" {
		scheme = strings.TrimSpace(strings.Split(xfProto, ",")[0])
	}
	host := strings.TrimSpace(r.Host)
	if xfHost := strings.TrimSpace(r.Header.Get("X-Forwarded-Host")); xfHost != "" {
		host = strings.TrimSpace(strings.Split(xfHost, ",")[0])
	}
	if host == "" {
		return ""
	}
	return scheme + "://" + host
}

func parseVersionFilters(r *http.Request) []string {
	out := make([]string, 0, 8)
	seen := map[string]struct{}{}
	if single := strings.TrimSpace(r.URL.Query().Get("version")); single != "" {
		seen[single] = struct{}{}
		out = append(out, single)
	}
	if raw := strings.TrimSpace(r.URL.Query().Get("versions")); raw != "" {
		for _, part := range strings.Split(raw, ",") {
			v := strings.TrimSpace(part)
			if v == "" {
				continue
			}
			if _, ok := seen[v]; ok {
				continue
			}
			seen[v] = struct{}{}
			out = append(out, v)
		}
	}
	return out
}

func inPlaceholders(n int) string {
	if n <= 0 {
		return ""
	}
	parts := make([]string, n)
	for i := 0; i < n; i++ {
		parts[i] = "?"
	}
	return strings.Join(parts, ",")
}

func inferProviderType(provider, providerBaseURL string) string {
	p := strings.ToLower(strings.TrimSpace(provider))
	if p == "github" || p == "gitlab" || p == "gitea" || p == "forgejo" {
		return p
	}
	b := strings.ToLower(strings.TrimSpace(providerBaseURL))
	switch {
	case strings.Contains(b, "github"):
		return "github"
	case strings.Contains(b, "gitlab"):
		return "gitlab"
	case strings.Contains(b, "gitea"):
		return "gitea"
	case strings.Contains(b, "forgejo"):
		return "forgejo"
	default:
		return p
	}
}

func buildProviderRepoURL(providerType, providerBaseURL, org, slug string) string {
	path := strings.Trim(strings.TrimSpace(org)+"/"+strings.TrimSpace(slug), "/")
	if path == "" {
		return ""
	}
	base := strings.TrimRight(strings.TrimSpace(providerBaseURL), "/")
	if base == "" {
		switch providerType {
		case "github":
			base = "https://github.com"
		case "gitlab":
			base = "https://gitlab.com"
		}
	}
	if base == "" {
		return path
	}
	return base + "/" + path
}

func buildSpamRepoURL(baseURL, providerType, org, slug, providerBaseURL string) string {
	path := strings.Trim(strings.TrimSpace(org)+"/"+strings.TrimSpace(slug), "/")
	if providerType == "" || path == "" {
		return ""
	}
	u := "/app/providers/repo?provider=" + providerType + "&path=" + path
	if strings.TrimSpace(providerBaseURL) != "" {
		u += "&base_url=" + strings.TrimSpace(providerBaseURL)
	}
	if baseURL == "" {
		return u
	}
	return baseURL + u
}

func loadContributorEmailsByRepo(db *gorm.DB, ctx context.Context, repoIDs []string) map[string]string {
	out := make(map[string]string, len(repoIDs))
	if len(repoIDs) == 0 {
		return out
	}
	type row struct {
		RepoID           string
		ContributorsJSON string
		CommitsJSON      string
	}
	var rows []row
	if err := db.WithContext(ctx).
		Table("repo_caches").
		Select("repo_id, contributors_json, commits_json").
		Where("repo_id IN ?", repoIDs).
		Find(&rows).Error; err != nil {
		return out
	}
	type contributor struct {
		Email string `json:"email"`
	}
	type commit struct {
		AuthorEmail string `json:"author_email"`
	}
	for _, r := range rows {
		set := map[string]struct{}{}

		if strings.TrimSpace(r.ContributorsJSON) != "" {
			var contributors []contributor
			if err := json.Unmarshal([]byte(r.ContributorsJSON), &contributors); err == nil {
				for _, c := range contributors {
					e := strings.TrimSpace(c.Email)
					if e == "" {
						continue
					}
					set[e] = struct{}{}
				}
			}
		}
		if strings.TrimSpace(r.CommitsJSON) != "" {
			var commits []commit
			if err := json.Unmarshal([]byte(r.CommitsJSON), &commits); err == nil {
				for _, c := range commits {
					e := strings.TrimSpace(c.AuthorEmail)
					if e == "" {
						continue
					}
					set[e] = struct{}{}
				}
			}
		}
		emails := make([]string, 0, len(set))
		for e := range set {
			emails = append(emails, e)
		}
		sort.Strings(emails)
		out[r.RepoID] = strings.Join(emails, ";")
	}
	return out
}

func queryDependencyAssetsForExport(db *gorm.DB, ctx context.Context, name, ecosystem string, versions []string, source string) ([]DependencyAsset, error) {
	cteParts := make([]string, 0, 3)
	args := make([]interface{}, 0, 10)
	selectParts := make([]string, 0, 2)
	if source == "" || source == "sbom" {
		sbomCTE := `
			sbom_assets AS (
				SELECT DISTINCT
					'REPO_COMMIT' as asset_type,
					r.id as repo_id,
					r.provider,
					r.org,
					r.slug,
					r.provider_instance_id,
					rc.commit_sha,
					COALESCE(s.version, NULLIF(s.purl_version, ''), '') as version,
					'sbom' as source,
					NULL as manifest_path,
					NULL as manifest_type,
					false as direct,
					NULL as scope,
					sb.created_at
				FROM sbom_component_view s
				JOIN sbom_bindings sb ON sb.sbom_id = s.sbom_id
				  AND sb.asset_type = 'REPO_COMMIT'
				  AND sb.asset_ref_id = s.asset_ref_id
				JOIN repo_commits rc ON rc.id = sb.asset_ref_id
				JOIN repos r ON r.id = rc.repo_id
				WHERE s.is_root = false
				  AND s.purl IS NOT NULL
				  AND s.kind = ?
				  AND COALESCE(s.package_name, s.normalized_name, s.name) = ?
		`
		args = append(args, ecosystem, name)
		if len(versions) > 0 {
			sbomCTE += ` AND COALESCE(s.version, NULLIF(s.purl_version, ''), '') IN (` + inPlaceholders(len(versions)) + `)`
			for _, v := range versions {
				args = append(args, v)
			}
		}
		sbomCTE += `)`
		cteParts = append(cteParts, sbomCTE)
		selectParts = append(selectParts, `SELECT * FROM sbom_assets`)
	}
	if source == "" || source == "manifest" {
		manifestCTE := `
			manifest_assets AS (
				SELECT
					'REPO_COMMIT' as asset_type,
					r.id as repo_id,
					r.provider,
					r.org,
					r.slug,
					r.provider_instance_id,
					'' as commit_sha,
					md.version,
					'manifest' as source,
					m.path as manifest_path,
					m.type as manifest_type,
					md.direct,
					md.scope,
					m.created_at
				FROM manifest_dependencies md
				JOIN manifests m ON m.id = md.manifest_id
				JOIN repos r ON r.id = m.repo_id
				WHERE md.name = ?
				  AND md.ecosystem = ?
		`
		args = append(args, name, ecosystem)
		if len(versions) > 0 {
			manifestCTE += ` AND md.version IN (` + inPlaceholders(len(versions)) + `)`
			for _, v := range versions {
				args = append(args, v)
			}
		}
		manifestCTE += `)`
		cteParts = append(cteParts, manifestCTE)
		selectParts = append(selectParts, `SELECT * FROM manifest_assets`)
	}
	assetsQuery := `
		WITH ` + strings.Join(cteParts, ",") + `,
		combined_assets AS (
			` + strings.Join(selectParts, ` UNION ALL `) + `
		)
		SELECT
			ca.asset_type,
			ca.repo_id,
			COALESCE(pi.display_name, ca.provider) as provider,
			ca.provider_instance_id as provider_id,
			ca.org,
			ca.slug,
			ca.commit_sha,
			ca.version,
			ca.source,
			ca.manifest_path,
			ca.manifest_type,
			ca.direct,
			ca.scope,
			COALESCE(pi.base_url, '') as provider_base_url
		FROM combined_assets ca
		LEFT JOIN provider_instances pi ON pi.id = ca.provider_instance_id
		ORDER BY ca.created_at DESC
	`
	rows, err := db.WithContext(ctx).Raw(assetsQuery, args...).Rows()
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	assets := make([]DependencyAsset, 0)
	for rows.Next() {
		var a DependencyAsset
		var commitSHA, manifestPath, manifestType, scope sql.NullString
		if err := rows.Scan(
			&a.AssetType, &a.RepoID, &a.Provider, &a.ProviderID, &a.Org, &a.Slug,
			&commitSHA, &a.Version, &a.Source, &manifestPath, &manifestType, &a.Direct, &scope, &a.ProviderBaseURL,
		); err != nil {
			continue
		}
		if commitSHA.Valid {
			v := commitSHA.String
			a.CommitSHA = &v
		}
		if manifestPath.Valid {
			v := manifestPath.String
			a.ManifestPath = &v
		}
		if manifestType.Valid {
			v := manifestType.String
			a.ManifestType = &v
		}
		if scope.Valid {
			v := scope.String
			a.Scope = &v
		}
		assets = append(assets, a)
	}
	return assets, nil
}

// UnifiedDependenciesResponse is the API response
type UnifiedDependenciesResponse struct {
	Dependencies []UnifiedDependency `json:"dependencies"`
	Total        int64               `json:"total"`
	Page         int                 `json:"page"`
	PerPage      int                 `json:"per_page"`
	TotalPages   int                 `json:"total_pages"`
}

// UnifiedDependenciesHandler merges SBOM components and manifest dependencies
func UnifiedDependenciesHandler(db *gorm.DB, authService *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if requireAuth(w, r, authService) == nil {
			return
		}

		page, _ := strconv.Atoi(r.URL.Query().Get("page"))
		if page < 1 {
			page = 1
		}
		perPage, _ := strconv.Atoi(r.URL.Query().Get("per_page"))
		if perPage < 1 || perPage > 100 {
			perPage = 50
		}

		search := r.URL.Query().Get("q")
		ecosystem := r.URL.Query().Get("ecosystem")
		repoID := r.URL.Query().Get("repo_id")
		source := r.URL.Query().Get("source") // "sbom", "manifest", or empty for both
		sortColumn := r.URL.Query().Get("sort")
		sortOrder := r.URL.Query().Get("order") // "asc" or "desc"
		parsedSearch, err := parseDependencySearchQuery(search)
		if err != nil {
			http.Error(w, "invalid dependency search query: "+err.Error(), http.StatusBadRequest)
			return
		}

		// Validate and set defaults for sorting
		if sortColumn == "" {
			sortColumn = "repo_count"
			sortOrder = "desc"
		}
		if sortOrder != "asc" && sortOrder != "desc" {
			sortOrder = "asc"
		}

		// Map frontend column names to SQL column names
		validSortColumns := map[string]string{
			"name":          "name",
			"ecosystem":     "ecosystem",
			"version_count": "version_count",
			"sbom_count":    "sbom_count",
			"repo_count":    "repo_count",
		}
		sqlSortColumn, ok := validSortColumns[sortColumn]
		if !ok {
			sqlSortColumn = "repo_count"
			sortOrder = "desc"
		}

		// Build the query. When a source filter is specified, short-circuit to avoid
		// scanning both sbom_component_view and manifest_dependencies unnecessarily.
		var query string
		args := []interface{}{}

		switch source {
		case "sbom":
			// Skip manifest_deps CTE entirely – only scan sbom_component_view.
			query = `
				WITH sbom_deps AS (
					SELECT
						scv.name,
						scv.ecosystem,
						MIN(NULLIF(split_part(scv.purl, '@', 1), '')) as purl,
						COUNT(DISTINCT COALESCE(scv.version, NULLIF(scv.purl_version, ''), '')) as version_count,
						COUNT(DISTINCT scv.sbom_id) as sbom_count,
						COUNT(DISTINCT rc.repo_id) as repo_count
					FROM (
						SELECT
							COALESCE(s.package_name, s.normalized_name, s.name) as name,
							s.kind as ecosystem,
							s.purl,
							s.purl_version,
							s.version,
							s.sbom_id,
							s.asset_type,
							s.asset_ref_id
						FROM sbom_component_view s
						WHERE s.is_root = false
						  AND s.purl IS NOT NULL
					) scv
					JOIN repo_commits rc ON rc.id = scv.asset_ref_id AND scv.asset_type = 'REPO_COMMIT'
					WHERE scv.name IS NOT NULL
			`
			if parsedSearch.Structured {
				predicate, predicateArgs := buildStructuredDependencyPredicate("scv.name", "COALESCE(scv.version, NULLIF(scv.purl_version, ''), '')", parsedSearch.Groups)
				if predicate != "" {
					query += ` AND ` + predicate
					args = append(args, predicateArgs...)
				}
			} else if search != "" {
				query += ` AND (scv.name ILIKE ? OR scv.purl ILIKE ?)`
				args = append(args, "%"+search+"%", "%"+search+"%")
			}
			if ecosystem != "" {
				query += ` AND scv.ecosystem = ?`
				args = append(args, ecosystem)
			}
			if repoID != "" {
				query += ` AND rc.repo_id = ?`
				args = append(args, repoID)
			}
			query += `
					GROUP BY scv.name, scv.ecosystem
				)
				SELECT name, ecosystem, purl, 'sbom' AS sources, version_count, sbom_count, repo_count,
				       false AS has_direct, NULL::text[] AS scopes, COUNT(*) OVER () AS total_count
				FROM sbom_deps
			`

		case "manifest":
			// Skip sbom_deps CTE entirely – only scan manifest_dependencies.
			query = `
				WITH manifest_deps AS (
					SELECT
						md.name,
						md.ecosystem,
						COUNT(DISTINCT md.version) as version_count,
						COUNT(DISTINCT m.id) as manifest_count,
						COUNT(DISTINCT m.repo_id) as repo_count,
						BOOL_OR(md.direct) as has_direct,
						ARRAY_AGG(DISTINCT md.scope) FILTER (WHERE md.scope IS NOT NULL) as scopes
					FROM manifest_dependencies md
					JOIN manifests m ON m.id = md.manifest_id
					WHERE 1=1
			`
			if parsedSearch.Structured {
				predicate, predicateArgs := buildStructuredDependencyPredicate("md.name", "COALESCE(md.version, '')", parsedSearch.Groups)
				if predicate != "" {
					query += ` AND ` + predicate
					args = append(args, predicateArgs...)
				}
			} else if search != "" {
				query += ` AND md.name ILIKE ?`
				args = append(args, "%"+search+"%")
			}
			if ecosystem != "" {
				query += ` AND md.ecosystem = ?`
				args = append(args, ecosystem)
			}
			if repoID != "" {
				query += ` AND m.repo_id = ?`
				args = append(args, repoID)
			}
			query += `
					GROUP BY md.name, md.ecosystem
				)
				SELECT name, ecosystem, NULL AS purl, 'manifest' AS sources, version_count, 0 AS sbom_count, repo_count,
				       has_direct, scopes, COUNT(*) OVER () AS total_count
				FROM manifest_deps
			`

		default:
			// Both sources (or "both" filter) – FULL OUTER JOIN across all data.
			query = `
				WITH sbom_deps AS (
					SELECT
						scv.name,
						scv.ecosystem,
						MIN(NULLIF(split_part(scv.purl, '@', 1), '')) as purl_base,
						'sbom' as source,
						COUNT(DISTINCT COALESCE(scv.version, NULLIF(scv.purl_version, ''), '')) as version_count,
						COUNT(DISTINCT scv.sbom_id) as sbom_count,
						COUNT(DISTINCT rc.repo_id) as repo_count
					FROM (
						SELECT
							COALESCE(s.package_name, s.normalized_name, s.name) as name,
							s.kind as ecosystem,
							s.purl,
							s.purl_version,
							s.version,
							s.sbom_id,
							s.asset_type,
							s.asset_ref_id
						FROM sbom_component_view s
						WHERE s.is_root = false
						  AND s.purl IS NOT NULL
					) scv
					JOIN repo_commits rc ON rc.id = scv.asset_ref_id AND scv.asset_type = 'REPO_COMMIT'
					WHERE scv.name IS NOT NULL
			`
			if parsedSearch.Structured {
				predicate, predicateArgs := buildStructuredDependencyPredicate("scv.name", "COALESCE(scv.version, NULLIF(scv.purl_version, ''), '')", parsedSearch.Groups)
				if predicate != "" {
					query += ` AND ` + predicate
					args = append(args, predicateArgs...)
				}
			} else if search != "" {
				query += ` AND (scv.name ILIKE ? OR scv.purl ILIKE ?)`
				args = append(args, "%"+search+"%", "%"+search+"%")
			}
			if ecosystem != "" {
				query += ` AND scv.ecosystem = ?`
				args = append(args, ecosystem)
			}
			if repoID != "" {
				query += ` AND rc.repo_id = ?`
				args = append(args, repoID)
			}
			query += `
					GROUP BY scv.name, scv.ecosystem
				),
				manifest_deps AS (
					SELECT
						md.name,
						md.ecosystem,
						'manifest' as source,
						COUNT(DISTINCT md.version) as version_count,
						COUNT(DISTINCT m.id) as manifest_count,
						COUNT(DISTINCT m.repo_id) as repo_count,
						BOOL_OR(md.direct) as has_direct,
						ARRAY_AGG(DISTINCT md.scope) FILTER (WHERE md.scope IS NOT NULL) as scopes
					FROM manifest_dependencies md
					JOIN manifests m ON m.id = md.manifest_id
					WHERE 1=1
			`
			if parsedSearch.Structured {
				predicate, predicateArgs := buildStructuredDependencyPredicate("md.name", "COALESCE(md.version, '')", parsedSearch.Groups)
				if predicate != "" {
					query += ` AND ` + predicate
					args = append(args, predicateArgs...)
				}
			} else if search != "" {
				query += ` AND md.name ILIKE ?`
				args = append(args, "%"+search+"%")
			}
			if ecosystem != "" {
				query += ` AND md.ecosystem = ?`
				args = append(args, ecosystem)
			}
			if repoID != "" {
				query += ` AND m.repo_id = ?`
				args = append(args, repoID)
			}
			query += `
					GROUP BY md.name, md.ecosystem
				),
				merged AS (
					SELECT
						COALESCE(s.name, m.name) as name,
						COALESCE(s.ecosystem, m.ecosystem) as ecosystem,
						s.purl_base as purl,
						CASE
							WHEN s.name IS NOT NULL AND m.name IS NOT NULL THEN 'both'
							WHEN s.name IS NOT NULL THEN 'sbom'
							ELSE 'manifest'
						END as sources,
						GREATEST(COALESCE(s.version_count, 0), COALESCE(m.version_count, 0)) as version_count,
						COALESCE(s.sbom_count, 0) as sbom_count,
						COALESCE(s.repo_count, m.repo_count, 0) as repo_count,
						COALESCE(m.has_direct, false) as has_direct,
						m.scopes
					FROM sbom_deps s
					FULL OUTER JOIN manifest_deps m
						ON s.name = m.name
						AND s.ecosystem = m.ecosystem
				)
				SELECT name, ecosystem, purl, sources, version_count, sbom_count, repo_count, has_direct, scopes, COUNT(*) OVER () AS total_count FROM merged
			`
			if source == "both" {
				query += ` WHERE sources = 'both'`
			}
		}

		// Apply sorting
		if sortOrder == "desc" {
			query += ` ORDER BY ` + sqlSortColumn + ` DESC`
		} else {
			query += ` ORDER BY ` + sqlSortColumn + ` ASC`
		}
		// Secondary sort by name for consistency
		query += `, name ASC`

		// Apply pagination
		offset := (page - 1) * perPage
		query += ` LIMIT ? OFFSET ?`
		args = append(args, interface{}(perPage), interface{}(offset))

		// Execute query — total count comes back as a window function column
		rows, err := db.WithContext(r.Context()).Raw(query, args...).Rows()
		if err != nil {
			log.Printf("unified deps query error: %v", err)
			http.Error(w, "database error", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		var total int64
		deps := make([]UnifiedDependency, 0)
		for rows.Next() {
			var dep UnifiedDependency
			var sources string
			var purl sql.NullString
			var scopes interface{}

			if err := rows.Scan(
				&dep.Name, &dep.Ecosystem, &purl,
				&sources, &dep.VersionCount,
				&dep.SBOMCount, &dep.RepoCount,
				&dep.HasDirect, &scopes, &total,
			); err != nil {
				log.Printf("scan error: %v", err)
				continue
			}

			if purl.Valid {
				dep.PURL = purl.String
			}

			// Parse scopes array from PostgreSQL
			if scopes != nil {
				if scopesBytes, ok := scopes.([]byte); ok {
					var scopeList []string
					if err := json.Unmarshal(scopesBytes, &scopeList); err == nil {
						dep.Scopes = scopeList
					}
				}
			}

			dep.Sources = []string{sources}
			deps = append(deps, dep)
		}

		totalPages := int(total) / perPage
		if int(total)%perPage > 0 {
			totalPages++
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(UnifiedDependenciesResponse{
			Dependencies: deps,
			Total:        total,
			Page:         page,
			PerPage:      perPage,
			TotalPages:   totalPages,
		})
	}
}

// DependencyDetail represents detailed information about a dependency from both SBOM and manifest sources
type DependencyDetail struct {
	Name         string                  `json:"name"`
	Ecosystem    string                  `json:"ecosystem"`
	PURL         string                  `json:"purl,omitempty"`
	VersionCount int                     `json:"version_count"`
	RepoCount    int                     `json:"repo_count"`
	ImageCount   int                     `json:"image_count"`
	Sources      []string                `json:"sources"`
	Versions     []DependencyVersionInfo `json:"versions"`
	Licenses     []string                `json:"licenses,omitempty"`
}

// DependencyVersionInfo describes a specific version of a dependency
type DependencyVersionInfo struct {
	Version   string   `json:"version"`
	RepoCount int      `json:"repo_count"`
	Sources   []string `json:"sources"` // "sbom", "manifest", or both
}

// DependencyAsset describes where a dependency is used (from SBOM or manifest)
type DependencyAsset struct {
	AssetType       string  `json:"asset_type"` // "REPO_COMMIT" only for now
	RepoID          string  `json:"repo_id,omitempty"`
	Provider        string  `json:"provider,omitempty"`
	ProviderID      string  `json:"provider_id,omitempty"`
	ProviderBaseURL string  `json:"provider_base_url,omitempty"`
	Org             string  `json:"org,omitempty"`
	Slug            string  `json:"slug,omitempty"`
	CommitSHA       *string `json:"commit_sha,omitempty"`
	Version         string  `json:"version"`
	Source          string  `json:"source"` // "sbom" or "manifest"
	ManifestPath    *string `json:"manifest_path,omitempty"`
	ManifestType    *string `json:"manifest_type,omitempty"`
	Direct          bool    `json:"direct,omitempty"`
	Scope           *string `json:"scope,omitempty"`
}

type dependencyAssetsResponse struct {
	Assets   []DependencyAsset `json:"assets"`
	Total    int64             `json:"total"`
	Page     int               `json:"page"`
	PageSize int               `json:"page_size"`
}

type RepoDependencyItem struct {
	Name      string   `json:"name"`
	Ecosystem string   `json:"ecosystem"`
	Version   string   `json:"version"`
	Sources   []string `json:"sources"`
	Direct    bool     `json:"direct"`
}

type repoDependenciesResponse struct {
	Dependencies []RepoDependencyItem `json:"dependencies"`
	Total        int                  `json:"total"`
}

// DependencyDetailHandler returns detailed information about a dependency by name and ecosystem
func DependencyDetailHandler(db *gorm.DB, authService *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if requireAuth(w, r, authService) == nil {
			return
		}

		name := r.URL.Query().Get("name")
		ecosystem := r.URL.Query().Get("ecosystem")

		if name == "" || ecosystem == "" {
			http.Error(w, "name and ecosystem required", http.StatusBadRequest)
			return
		}

		// Aggregate versions from both SBOM and manifest sources.
		// purl_base is computed once in the sbom_versions CTE and projected via MIN() OVER ()
		// to avoid a second round-trip for the PURL lookup.
		versionsQuery := `
			WITH sbom_versions AS (
				SELECT
					COALESCE(s.version, NULLIF(s.purl_version, ''), '') as version,
					COUNT(DISTINCT s.asset_ref_id) as repo_count,
					MIN(NULLIF(split_part(s.purl, '@', 1), '')) as purl_base,
					MIN(NULLIF(s.licenses, '')) as licenses,
					'sbom' as source
				FROM sbom_component_view s
				WHERE s.is_root = false
				  AND s.purl IS NOT NULL
				  AND COALESCE(s.package_name, s.normalized_name, s.name) = ? AND s.kind = ?
				  AND s.asset_type = 'REPO_COMMIT'
				GROUP BY COALESCE(s.version, NULLIF(s.purl_version, ''), '')
			),
			manifest_versions AS (
				SELECT
					md.version,
					COUNT(DISTINCT m.repo_id) as repo_count,
					NULL::text as purl_base,
					NULL::text as licenses,
					'manifest' as source
				FROM manifest_dependencies md
				JOIN manifests m ON m.id = md.manifest_id
				WHERE md.name = ? AND md.ecosystem = ?
				GROUP BY md.version
			),
			merged_versions AS (
				SELECT
					COALESCE(s.version, m.version) as version,
					COALESCE(s.repo_count, 0) + COALESCE(m.repo_count, 0) as repo_count,
					CASE
						WHEN s.version IS NOT NULL AND m.version IS NOT NULL THEN 'both'
						WHEN s.version IS NOT NULL THEN 'sbom'
						ELSE 'manifest'
					END as sources,
					s.purl_base,
					COALESCE(s.licenses, '') as licenses
				FROM sbom_versions s
				FULL OUTER JOIN manifest_versions m ON s.version = m.version
			)
			SELECT version, repo_count, sources, MIN(purl_base) OVER () AS overall_purl, MIN(NULLIF(licenses, '')) OVER () AS overall_licenses
			FROM merged_versions
			ORDER BY repo_count DESC, version DESC
			LIMIT 100
		`

		rows, err := db.WithContext(r.Context()).Raw(versionsQuery, name, ecosystem, name, ecosystem).Rows()
		if err != nil {
			http.Error(w, "query failed", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		versions := make([]DependencyVersionInfo, 0)
		totalRepoCount := 0
		var overallPURL sql.NullString
		var overallLicenses sql.NullString
		for rows.Next() {
			var v DependencyVersionInfo
			var sources string
			if err := rows.Scan(&v.Version, &v.RepoCount, &sources, &overallPURL, &overallLicenses); err != nil {
				log.Printf("version scan error: %v", err)
				continue
			}
			v.Sources = []string{sources}
			versions = append(versions, v)
			totalRepoCount += v.RepoCount
		}

		// Determine sources from versions
		sources := make([]string, 0)
		hasSBOM := false
		hasManifest := false

		for _, v := range versions {
			if len(v.Sources) > 0 {
				switch v.Sources[0] {
				case "sbom":
					hasSBOM = true
				case "manifest":
					hasManifest = true
				case "both":
					hasSBOM = true
					hasManifest = true
				}
			}
		}

		if hasSBOM && hasManifest {
			sources = []string{"both"}
		} else if hasSBOM {
			sources = []string{"sbom"}
		} else if hasManifest {
			sources = []string{"manifest"}
		}

		if len(versions) == 0 {
			http.Error(w, "dependency not found", http.StatusNotFound)
			return
		}

		var licenses []string
		if overallLicenses.Valid && overallLicenses.String != "" {
			for _, l := range strings.Split(overallLicenses.String, ",") {
				l = strings.TrimSpace(l)
				if l != "" {
					licenses = append(licenses, l)
				}
			}
		}

		detail := DependencyDetail{
			Name:         name,
			Ecosystem:    ecosystem,
			PURL:         overallPURL.String,
			VersionCount: len(versions),
			RepoCount:    totalRepoCount,
			ImageCount:   0, // Images only from SBOMs, we can calculate this if needed
			Sources:      sources,
			Versions:     versions,
			Licenses:     licenses,
		}

		writeJSON(w, http.StatusOK, detail)
	}
}

// DependencyAssetsHandler returns repos/images using a dependency by name and ecosystem
func DependencyAssetsHandler(db *gorm.DB, authService *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if requireAuth(w, r, authService) == nil {
			return
		}

		name := r.URL.Query().Get("name")
		ecosystem := r.URL.Query().Get("ecosystem")
		versions := parseVersionFilters(r)
		source := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("source")))

		if name == "" || ecosystem == "" {
			http.Error(w, "name and ecosystem required", http.StatusBadRequest)
			return
		}
		if source != "" && source != "sbom" && source != "manifest" && source != "both" {
			http.Error(w, "invalid source", http.StatusBadRequest)
			return
		}
		if source == "both" {
			// For assets, "both" behaves as "all sources".
			source = ""
		}

		page, _ := strconv.Atoi(r.URL.Query().Get("page"))
		if page < 1 {
			page = 1
		}
		pageSize, _ := strconv.Atoi(r.URL.Query().Get("page_size"))
		if pageSize < 1 || pageSize > 200 {
			pageSize = 100
		}

		cteParts := make([]string, 0, 3)
		args := make([]interface{}, 0, 10)
		selectParts := make([]string, 0, 2)

		if source == "" || source == "sbom" {
			sbomCTE := `
				sbom_assets AS (
					SELECT DISTINCT
						'REPO_COMMIT' as asset_type,
						r.id as repo_id,
						r.provider,
						r.org,
						r.slug,
						r.provider_instance_id,
						rc.commit_sha,
						COALESCE(s.version, NULLIF(s.purl_version, ''), '') as version,
						'sbom' as source,
						NULL as manifest_path,
						NULL as manifest_type,
						false as direct,
						NULL as scope,
						sb.created_at
					FROM sbom_component_view s
					JOIN sbom_bindings sb ON sb.sbom_id = s.sbom_id
					  AND sb.asset_type = 'REPO_COMMIT'
					  AND sb.asset_ref_id = s.asset_ref_id
					JOIN repo_commits rc ON rc.id = sb.asset_ref_id
					JOIN repos r ON r.id = rc.repo_id
					WHERE s.is_root = false
					  AND s.purl IS NOT NULL
					  AND s.kind = ?
					  AND COALESCE(s.package_name, s.normalized_name, s.name) = ?
			`
			args = append(args, ecosystem, name)
			if len(versions) > 0 {
				sbomCTE += ` AND COALESCE(s.version, NULLIF(s.purl_version, ''), '') IN (` + inPlaceholders(len(versions)) + `)`
				for _, v := range versions {
					args = append(args, v)
				}
			}
			sbomCTE += `
				)
			`
			cteParts = append(cteParts, sbomCTE)
			selectParts = append(selectParts, `SELECT * FROM sbom_assets`)
		}

		if source == "" || source == "manifest" {
			manifestCTE := `
				manifest_assets AS (
					SELECT
						'REPO_COMMIT' as asset_type,
						r.id as repo_id,
						r.provider,
						r.org,
						r.slug,
						r.provider_instance_id,
						'' as commit_sha,
						md.version,
						'manifest' as source,
						m.path as manifest_path,
						m.type as manifest_type,
						md.direct,
						md.scope,
						m.created_at
					FROM manifest_dependencies md
					JOIN manifests m ON m.id = md.manifest_id
					JOIN repos r ON r.id = m.repo_id
					WHERE md.name = ?
					  AND md.ecosystem = ?
			`
			args = append(args, name, ecosystem)
			if len(versions) > 0 {
				manifestCTE += ` AND md.version IN (` + inPlaceholders(len(versions)) + `)`
				for _, v := range versions {
					args = append(args, v)
				}
			}
			manifestCTE += `
				)
			`
			cteParts = append(cteParts, manifestCTE)
			selectParts = append(selectParts, `SELECT * FROM manifest_assets`)
		}

		countQuery := `
			WITH ` + strings.Join(cteParts, ",") + `,
			combined_assets AS (
				` + strings.Join(selectParts, `
				UNION ALL
				`) + `
			)
			SELECT COUNT(*) FROM combined_assets
		`

		var total int64
		if err := db.WithContext(r.Context()).Raw(countQuery, args...).Scan(&total).Error; err != nil {
			http.Error(w, "query failed", http.StatusInternalServerError)
			return
		}

		assetsQuery := `
			WITH ` + strings.Join(cteParts, ",") + `,
			combined_assets AS (
				` + strings.Join(selectParts, `
				UNION ALL
				`) + `
			)
			SELECT
				ca.asset_type,
				ca.repo_id,
				COALESCE(pi.display_name, ca.provider) as provider,
				ca.provider_instance_id as provider_id,
				ca.org,
				ca.slug,
				ca.commit_sha,
				ca.version,
				ca.source,
				ca.manifest_path,
				ca.manifest_type,
				ca.direct,
				ca.scope,
				COALESCE(pi.base_url, '') as provider_base_url
			FROM combined_assets ca
			LEFT JOIN provider_instances pi ON pi.id = ca.provider_instance_id
			ORDER BY ca.created_at DESC
			LIMIT ? OFFSET ?
		`

		queryArgs := append(make([]interface{}, 0, len(args)+2), args...)
		queryArgs = append(queryArgs, pageSize, (page-1)*pageSize)
		rows, err := db.WithContext(r.Context()).Raw(assetsQuery, queryArgs...).Rows()
		if err != nil {
			http.Error(w, "query failed", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		assets := make([]DependencyAsset, 0)
		for rows.Next() {
			var a DependencyAsset
			var commitSHA, manifestPath, manifestType, scope sql.NullString

			if err := rows.Scan(
				&a.AssetType, &a.RepoID, &a.Provider, &a.ProviderID, &a.Org, &a.Slug,
				&commitSHA, &a.Version, &a.Source, &manifestPath,
				&manifestType, &a.Direct, &scope, &a.ProviderBaseURL,
			); err != nil {
				log.Printf("asset scan error: %v", err)
				continue
			}

			// Convert sql.NullString to *string (create copies to avoid pointer issues)
			if commitSHA.Valid {
				val := commitSHA.String
				a.CommitSHA = &val
			}
			if manifestPath.Valid {
				val := manifestPath.String
				a.ManifestPath = &val
			}
			if manifestType.Valid {
				val := manifestType.String
				a.ManifestType = &val
			}
			if scope.Valid {
				val := scope.String
				a.Scope = &val
			}

			assets = append(assets, a)
		}

		writeJSON(w, http.StatusOK, dependencyAssetsResponse{
			Assets:   assets,
			Total:    total,
			Page:     page,
			PageSize: pageSize,
		})
	}
}

// RepoDependenciesListHandler returns merged dependency rows for a single repository.
func RepoDependenciesListHandler(db *gorm.DB, authService *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if requireAuth(w, r, authService) == nil {
			return
		}

		repoID := strings.TrimSpace(r.URL.Query().Get("repo_id"))
		if repoID == "" {
			http.Error(w, "repo_id required", http.StatusBadRequest)
			return
		}

		query := `
			WITH sbom_rows AS (
				SELECT DISTINCT
					COALESCE(s.package_name, s.normalized_name, s.name) AS name,
					s.kind AS ecosystem,
					COALESCE(s.version, NULLIF(s.purl_version, ''), '') AS version
				FROM sbom_component_view s
				JOIN repo_commits rc ON rc.id = s.asset_ref_id
				WHERE s.asset_type = 'REPO_COMMIT'
				  AND s.is_root = false
				  AND s.purl IS NOT NULL
				  AND rc.repo_id = ?
				  AND COALESCE(s.package_name, s.normalized_name, s.name) IS NOT NULL
			),
			manifest_rows AS (
				SELECT
					md.name,
					md.ecosystem,
					COALESCE(md.version, '') AS version,
					BOOL_OR(md.direct) AS direct
				FROM manifest_dependencies md
				JOIN manifests m ON m.id = md.manifest_id
				WHERE m.repo_id = ?
				  AND md.name IS NOT NULL
				GROUP BY md.name, md.ecosystem, COALESCE(md.version, '')
			),
			merged AS (
				SELECT
					COALESCE(s.name, m.name) AS name,
					COALESCE(s.ecosystem, m.ecosystem) AS ecosystem,
					COALESCE(s.version, m.version) AS version,
					(s.name IS NOT NULL) AS has_sbom,
					(m.name IS NOT NULL) AS has_manifest,
					COALESCE(m.direct, false) AS direct
				FROM sbom_rows s
				FULL OUTER JOIN manifest_rows m
					ON s.name = m.name
					AND s.ecosystem = m.ecosystem
					AND s.version = m.version
			)
			SELECT
				name,
				ecosystem,
				version,
				has_sbom,
				has_manifest,
				direct
			FROM merged
			ORDER BY
				direct DESC,
				LOWER(name) ASC,
				LOWER(version) ASC
		`

		rows, err := db.WithContext(r.Context()).Raw(query, repoID, repoID).Rows()
		if err != nil {
			log.Printf("repo dependencies query error: %v", err)
			http.Error(w, "database error", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		dependencies := make([]RepoDependencyItem, 0)
		for rows.Next() {
			var item RepoDependencyItem
			var hasSBOM, hasManifest bool
			if err := rows.Scan(&item.Name, &item.Ecosystem, &item.Version, &hasSBOM, &hasManifest, &item.Direct); err != nil {
				log.Printf("repo dependencies scan error: %v", err)
				continue
			}
			switch {
			case hasSBOM && hasManifest:
				item.Sources = []string{"manifest", "sbom"}
			case hasManifest:
				item.Sources = []string{"manifest"}
			case hasSBOM:
				item.Sources = []string{"sbom"}
			default:
				item.Sources = []string{}
			}
			dependencies = append(dependencies, item)
		}

		writeJSON(w, http.StatusOK, repoDependenciesResponse{
			Dependencies: dependencies,
			Total:        len(dependencies),
		})
	}
}
