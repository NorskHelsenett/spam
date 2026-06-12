package uiapi

import (
	"context"
	"database/sql"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"log"
	"net/http"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/NorskHelsenett/spam/internal/acl"
	"github.com/NorskHelsenett/spam/internal/assets"
	"github.com/NorskHelsenett/spam/internal/auth"
	"github.com/NorskHelsenett/spam/internal/cache"
	"github.com/NorskHelsenett/spam/internal/vulnerabilities"
	"gorm.io/gorm"
)

// UnifiedDependency combines data from SBOMs and manifests
type UnifiedDependency struct {
	Name         string   `json:"name"`
	Ecosystem    string   `json:"ecosystem"`
	PURL         string   `json:"purl,omitempty"`   // PURL without version
	Sources      []string `json:"sources"`          // ["sbom", "manifest", "image"]
	VersionCount int      `json:"version_count"`    // How many different versions
	SBOMCount    int      `json:"sbom_count"`       // How many SBOMs contain this
	RepoCount    int      `json:"repo_count"`       // How many repos use this
	ImageCount   int      `json:"image_count"`      // How many container images use this
	HasDirect    bool     `json:"has_direct"`       // At least one version is direct
	Scopes       []string `json:"scopes,omitempty"` // All unique scopes across versions
}

// dependencyExportCTEs is the shared WITH-clause body for both CSV export
// queries. merged holds repo-bound rows (SBOM ⋈ manifest per
// repo+component+version); image_rows holds image-bound SBOM components,
// which the list endpoint also counts and which would otherwise vanish from
// exports (base-image OS packages live only here). merged_all unions both:
// image rows carry the image reference in image_ref and inherit the source
// repo for ACL/email purposes only when the image's source is verified —
// same rule as acl.ReadableImageClause.
const dependencyExportCTEs = `
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
	),
	image_rows AS (
		SELECT DISTINCT
			CASE WHEN id.verified_source = true AND COALESCE(id.source_repo_id, '') <> ''
				THEN id.source_repo_id ELSE NULL END as repo_id,
			(id.registry || '/' || id.repository) as image_ref,
			COALESCE(s.version, NULLIF(s.purl_version, ''), '') as version,
			NULLIF(s.purl, '') as component_purl,
			COALESCE(s.package_name, s.normalized_name, s.name) as component_name,
			s.kind as ecosystem
		FROM sbom_component_view s
		JOIN image_digests id ON id.id = s.asset_ref_id
		WHERE s.is_root = false
		  AND s.purl IS NOT NULL
		  AND s.asset_type = 'IMAGE_DIGEST'
		  AND COALESCE(s.package_name, s.normalized_name, s.name) IS NOT NULL
	),
	merged_all AS (
		SELECT repo_id, provider, org, slug, NULL::text as image_ref,
			version, component_purl, component_name, ecosystem, has_sbom, has_manifest
		FROM merged
		UNION ALL
		SELECT repo_id, NULL::text, NULL::text, NULL::text, image_ref,
			version, component_purl, component_name, ecosystem, true, false
		FROM image_rows
	)
`

// appendDependencyExportFilters appends the shared WHERE conditions for the
// export queries: search, ecosystem, repo and source filters over merged_all.
// Source semantics mirror the list endpoint so the export contains every
// package the filtered table shows: "sbom"/"manifest" mean "has data from
// that source" (not exclusively), and "both" is package-level — a package
// verified by both sources anywhere, not only repo+version tuples present
// in both.
func appendDependencyExportFilters(query string, args []interface{}, parsedSearch parsedDependencySearch, search, ecosystem, repoID, source string) (string, []interface{}) {
	if parsedSearch.Structured {
		predicate, predicateArgs := buildStructuredDependencyPredicate("merged_all.component_name", "merged_all.version", parsedSearch.Groups)
		if predicate != "" {
			query += ` AND ` + predicate
			args = append(args, predicateArgs...)
		}
	} else if search != "" {
		query += ` AND (merged_all.component_name ILIKE ? OR merged_all.component_purl ILIKE ?)`
		args = append(args, "%"+search+"%", "%"+search+"%")
	}
	if ecosystem != "" {
		query += ` AND merged_all.ecosystem = ?`
		args = append(args, ecosystem)
	}
	if repoID != "" {
		query += ` AND merged_all.repo_id = ?`
		args = append(args, repoID)
	}

	switch source {
	case "sbom":
		query += ` AND merged_all.has_sbom = true`
	case "manifest":
		query += ` AND merged_all.has_manifest = true`
	case "both":
		sub := `SELECT component_name, ecosystem FROM merged_all`
		if repoID != "" {
			sub += ` WHERE repo_id = ?`
			args = append(args, repoID)
		}
		sub += ` GROUP BY component_name, ecosystem HAVING BOOL_OR(has_sbom) AND BOOL_OR(has_manifest)`
		query += ` AND (merged_all.component_name, merged_all.ecosystem) IN (` + sub + `)`
	}
	return query, args
}

// buildDependencyExportQuery assembles the SQL for the forensics CSV export.
// spam_url builds its query-string '?' via chr(63): GORM's bind-var scanner
// replaces every literal '?' in raw SQL, even inside string literals, so a
// plain '?' would silently consume the first filter argument.
func buildDependencyExportQuery(aclSQL string, aclArgs []interface{}, parsedSearch parsedDependencySearch, search, ecosystem, repoID, source string) (string, []interface{}) {
	query := dependencyExportCTEs + `
		SELECT DISTINCT
			COALESCE(merged_all.image_ref, concat_ws('/', merged_all.provider, merged_all.org, merged_all.slug)) as repo,
			merged_all.version,
			merged_all.component_purl,
			merged_all.component_name,
			merged_all.ecosystem,
			CASE WHEN merged_all.image_ref IS NULL THEN
				('/providers/repo' || chr(63) || 'provider=' || merged_all.provider || '&path=' || merged_all.org || '/' || merged_all.slug
					|| CASE WHEN COALESCE(pi.base_url, '') <> '' THEN '&base_url=' || pi.base_url ELSE '' END
				)
			ELSE '' END AS spam_url
		FROM merged_all
		LEFT JOIN repos r ON r.id = merged_all.repo_id
		LEFT JOIN provider_instances pi ON pi.id = r.provider_instance_id
		WHERE ` + aclSQL

	args := []interface{}{}
	args = append(args, aclArgs...)
	query, args = appendDependencyExportFilters(query, args, parsedSearch, search, ecosystem, repoID, source)
	query += ` ORDER BY repo ASC, merged_all.component_name ASC, merged_all.version ASC`
	return query, args
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
		if repoID != "" {
			if ok, err := canReadRepoByID(r, db, repoID); err != nil || !ok {
				notFoundOrForbidden(w)
				return
			}
		}
		repoClause, err := acl.ReadableRepoClause(r.Context(), acl.ProviderFromRequest(r), acl.SubjectFromRequest(r), "r")
		if err != nil {
			http.Error(w, "failed to scope results", http.StatusInternalServerError)
			return
		}
		aclSQL, aclArgs := aclWhereFragment(repoClause)
		query, args := buildDependencyExportQuery(aclSQL, aclArgs, parsedSearch, search, ecosystem, repoID, source)

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

// buildDependencyFullExportQuery assembles the SQL for the full CSV export
// (forensics columns plus repo URL inputs and repo_id for the contributor
// email lookup). Same CTEs and source semantics as buildDependencyExportQuery.
func buildDependencyFullExportQuery(aclSQL string, aclArgs []interface{}, parsedSearch parsedDependencySearch, search, ecosystem, repoID, source string) (string, []interface{}) {
	query := dependencyExportCTEs + `
		SELECT DISTINCT
			merged_all.repo_id,
			COALESCE(merged_all.image_ref, concat_ws('/', merged_all.provider, merged_all.org, merged_all.slug)) as repo,
			merged_all.version,
			merged_all.component_purl,
			merged_all.component_name,
			merged_all.ecosystem,
			COALESCE(merged_all.provider, '') as provider,
			COALESCE(merged_all.org, '') as org,
			COALESCE(merged_all.slug, '') as slug,
			COALESCE(pi.base_url, '') as provider_base_url
		FROM merged_all
		LEFT JOIN repos r ON r.id = merged_all.repo_id
		LEFT JOIN provider_instances pi ON pi.id = r.provider_instance_id
		WHERE ` + aclSQL

	args := []interface{}{}
	args = append(args, aclArgs...)
	query, args = appendDependencyExportFilters(query, args, parsedSearch, search, ecosystem, repoID, source)
	query += ` ORDER BY repo ASC, merged_all.component_name ASC, merged_all.version ASC`
	return query, args
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
		if repoID != "" {
			if ok, err := canReadRepoByID(r, db, repoID); err != nil || !ok {
				notFoundOrForbidden(w)
				return
			}
		}
		repoClause, err := acl.ReadableRepoClause(r.Context(), acl.ProviderFromRequest(r), acl.SubjectFromRequest(r), "r")
		if err != nil {
			http.Error(w, "failed to scope results", http.StatusInternalServerError)
			return
		}
		aclSQL, aclArgs := aclWhereFragment(repoClause)
		query, args := buildDependencyFullExportQuery(aclSQL, aclArgs, parsedSearch, search, ecosystem, repoID, source)

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

		// Post-filter by readable repos. Image-bound rows (AssetType
		// 'IMAGE_DIGEST') are kept only when their image's
		// source_repo_id is readable AND verified_source is true; any
		// asset with an unresolved RepoID falls back to admin-only.
		readable, unrestricted, err := readableRepoIDSet(r, db)
		if err != nil {
			http.Error(w, "failed to scope results", http.StatusInternalServerError)
			return
		}
		isAdmin := acl.SubjectFromRequest(r).IsAdmin
		if !unrestricted {
			filtered := assets[:0]
			for _, a := range assets {
				if a.RepoID == "" {
					if isAdmin {
						filtered = append(filtered, a)
					}
					continue
				}
				if _, ok := readable[a.RepoID]; ok {
					filtered = append(filtered, a)
				}
			}
			assets = filtered
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
				repository = strings.Trim(strings.TrimSpace(a.ImageRegistry)+"/"+strings.TrimSpace(a.ImageRepository), "/")
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
	u := "/providers/repo?provider=" + providerType + "&path=" + path
	if strings.TrimSpace(providerBaseURL) != "" {
		u += "&base_url=" + strings.TrimSpace(providerBaseURL)
	}
	if baseURL == "" {
		return u
	}
	return baseURL + u
}

// loadContributorEmailsByRepo merges contributor emails from two sources:
// repo_commits.author_email (captured durably by the runner via git log)
// and the provider cache in kv_store (repo:cache:<id> — contributors and
// recent commits from the provider API). The legacy repo_caches table this
// used to read was transient (d371158→65632a7); fresh installs never have
// it, so reading it returned no emails at all.
func loadContributorEmailsByRepo(db *gorm.DB, ctx context.Context, repoIDs []string) map[string]string {
	out := make(map[string]string, len(repoIDs))
	if len(repoIDs) == 0 {
		return out
	}
	sets := make(map[string]map[string]struct{}, len(repoIDs))
	add := func(repoID, email string) {
		e := strings.TrimSpace(email)
		if e == "" {
			return
		}
		set, ok := sets[repoID]
		if !ok {
			set = map[string]struct{}{}
			sets[repoID] = set
		}
		set[e] = struct{}{}
	}

	type commitRow struct {
		RepoID      string
		AuthorEmail string
	}
	var commitRows []commitRow
	if err := db.WithContext(ctx).
		Table("repo_commits").
		Select("DISTINCT repo_id, author_email").
		Where("repo_id IN ? AND COALESCE(author_email, '') <> ''", repoIDs).
		Find(&commitRows).Error; err != nil {
		log.Printf("contributor emails: repo_commits query error: %v", err)
	}
	for _, r := range commitRows {
		add(r.RepoID, r.AuthorEmail)
	}

	keys := make([]string, 0, len(repoIDs))
	keyToRepo := make(map[string]string, len(repoIDs))
	for _, id := range repoIDs {
		k := assets.RepoCacheKey(id)
		keys = append(keys, k)
		keyToRepo[k] = id
	}
	type kvRow struct {
		Key   string
		Value []byte
	}
	var kvRows []kvRow
	if err := db.WithContext(ctx).
		Table("kv_store").
		Select("key, value").
		Where("key IN ? AND (expires_at IS NULL OR expires_at > now())", keys).
		Find(&kvRows).Error; err != nil {
		log.Printf("contributor emails: kv_store query error: %v", err)
	}
	type contributor struct {
		Email string `json:"email"`
	}
	type commit struct {
		AuthorEmail string `json:"author_email"`
	}
	for _, row := range kvRows {
		repoID := keyToRepo[row.Key]
		var data assets.RepoCacheData
		if err := json.Unmarshal(row.Value, &data); err != nil {
			continue
		}
		if strings.TrimSpace(data.ContributorsJSON) != "" {
			var contributors []contributor
			if err := json.Unmarshal([]byte(data.ContributorsJSON), &contributors); err == nil {
				for _, c := range contributors {
					add(repoID, c.Email)
				}
			}
		}
		if strings.TrimSpace(data.CommitsJSON) != "" {
			var commits []commit
			if err := json.Unmarshal([]byte(data.CommitsJSON), &commits); err == nil {
				for _, c := range commits {
					add(repoID, c.AuthorEmail)
				}
			}
		}
	}

	for repoID, set := range sets {
		emails := make([]string, 0, len(set))
		for e := range set {
			emails = append(emails, e)
		}
		sort.Strings(emails)
		out[repoID] = strings.Join(emails, ";")
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
					NULL::text as image_registry,
					NULL::text as image_repository,
					NULL::text as image_digest,
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

		// Image-bound SBOM components (asset_type IMAGE_DIGEST). repo_id
		// resolves to the image's source repo only when the source is
		// verified — same rule as acl.ReadableImageClause — so the caller's
		// ACL post-filter and the contributor-email lookup both work;
		// unverified/unresolved images keep repo_id NULL and fall back to
		// admin-only in the caller.
		imageCTE := `
			image_assets AS (
				SELECT DISTINCT
					'IMAGE_DIGEST' as asset_type,
					CASE WHEN id.verified_source = true AND COALESCE(id.source_repo_id, '') <> ''
						THEN id.source_repo_id ELSE NULL END as repo_id,
					NULL::text as provider,
					NULL::text as org,
					NULL::text as slug,
					NULL::text as provider_instance_id,
					NULL::text as commit_sha,
					id.registry as image_registry,
					id.repository as image_repository,
					id.digest as image_digest,
					COALESCE(s.version, NULLIF(s.purl_version, ''), '') as version,
					'sbom' as source,
					NULL as manifest_path,
					NULL as manifest_type,
					false as direct,
					NULL as scope,
					sb.created_at
				FROM sbom_component_view s
				JOIN sbom_bindings sb ON sb.sbom_id = s.sbom_id
				  AND sb.asset_type = 'IMAGE_DIGEST'
				  AND sb.asset_ref_id = s.asset_ref_id
				JOIN image_digests id ON id.id = sb.asset_ref_id
				WHERE s.is_root = false
				  AND s.purl IS NOT NULL
				  AND s.kind = ?
				  AND COALESCE(s.package_name, s.normalized_name, s.name) = ?
		`
		args = append(args, ecosystem, name)
		if len(versions) > 0 {
			imageCTE += ` AND COALESCE(s.version, NULLIF(s.purl_version, ''), '') IN (` + inPlaceholders(len(versions)) + `)`
			for _, v := range versions {
				args = append(args, v)
			}
		}
		imageCTE += `)`
		cteParts = append(cteParts, imageCTE)
		selectParts = append(selectParts, `SELECT * FROM image_assets`)
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
					NULL::text as image_registry,
					NULL::text as image_repository,
					NULL::text as image_digest,
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
			COALESCE(ca.repo_id, '') as repo_id,
			COALESCE(pi.display_name, ca.provider, '') as provider,
			COALESCE(ca.provider_instance_id, '') as provider_id,
			COALESCE(ca.org, '') as org,
			COALESCE(ca.slug, '') as slug,
			ca.commit_sha,
			COALESCE(ca.image_registry, '') as image_registry,
			COALESCE(ca.image_repository, '') as image_repository,
			COALESCE(ca.image_digest, '') as image_digest,
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
			&commitSHA, &a.ImageRegistry, &a.ImageRepository, &a.ImageDigest,
			&a.Version, &a.Source, &manifestPath, &manifestType, &a.Direct, &scope, &a.ProviderBaseURL,
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

// UnifiedDependenciesResponse is the API response. HasMore is the
// limit+1 trick: the handler asks the DB for one row past the page,
// drops it before serialising, and reports HasMore=true. Replaces the
// old COUNT(*) OVER () total — at scale, computing the total dominated
// the query (full GROUP BY across both sbom_component_view and
// manifest_dependencies) and made `?q=spa` searches unusable.
type UnifiedDependenciesResponse struct {
	Dependencies []UnifiedDependency `json:"dependencies"`
	Page         int                 `json:"page"`
	PerPage      int                 `json:"per_page"`
	HasMore      bool                `json:"has_more"`
}

const unifiedDepsCacheKeyPrefix = "deps:unified:v1:"

// unifiedDepsCacheTTL is intentionally long because invalidation is
// driven by the watermark (sbom_component_view refresh + latest
// manifest_dependencies row) — TTL only catches orphan keys whose
// watermark moved past them.
const unifiedDepsCacheTTL = 30 * time.Minute

// unifiedDepsCacheEntry is the cached response plus the watermark at
// compute time. ACL-scoped requests skip the cache entirely; cross-
// repo aggregates are admin-only in Phase 3 so all callers see the
// same data and key collisions are not a privacy issue.
type unifiedDepsCacheEntry struct {
	Watermark time.Time                    `json:"watermark"`
	Response  UnifiedDependenciesResponse  `json:"response"`
}

// unifiedDepsCacheKey hashes every input that affects the response.
// 8-byte fnv-64a collisions are harmless: the watermark check inside
// the entry would still gate freshness, and the alternative response
// would have been computed against identical filters anyway.
func unifiedDepsCacheKey(page, perPage int, search, ecosystem, source, sortColumn, sortOrder string) string {
	h := fnv.New64a()
	enc := json.NewEncoder(h)
	_ = enc.Encode(struct {
		Page, PerPage                                      int
		Search, Ecosystem, Source, SortColumn, SortOrder   string
	}{page, perPage, search, ecosystem, source, sortColumn, sortOrder})
	return fmt.Sprintf("%s%x", unifiedDepsCacheKeyPrefix, h.Sum64())
}

// unifiedDepsWatermark returns the latest moment at which the
// underlying data could have changed: the SBOM materialized view
// refresh or the most recent manifest_dependency insert. Mirrors the
// app_summary pattern so cache invalidation is driven by data
// freshness, not wall-clock TTL.
func unifiedDepsWatermark(ctx context.Context, db *gorm.DB) time.Time {
	var sbomRefreshedAt time.Time
	db.WithContext(ctx).Raw(
		"SELECT refreshed_at FROM materialized_view_refreshes WHERE name = 'sbom_component_view' LIMIT 1",
	).Scan(&sbomRefreshedAt)

	var latestManifestCreatedAt time.Time
	db.WithContext(ctx).Raw(
		"SELECT COALESCE(MAX(created_at), TIMESTAMPTZ 'epoch') FROM manifest_dependencies",
	).Scan(&latestManifestCreatedAt)

	if latestManifestCreatedAt.After(sbomRefreshedAt) {
		return latestManifestCreatedAt
	}
	return sbomRefreshedAt
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

		// When scoped to a specific repo, gate by ACL up-front so we
		// never expose dependencies of a repo the caller can't read.
		// The cross-repo aggregate path is not ACL-filtered in Phase 3
		// and falls back to the migration grant — Phase 4 will scope
		// aggregates per-subject.
		if repoID != "" {
			if ok, err := canReadRepoByID(r, db, repoID); err != nil || !ok {
				notFoundOrForbidden(w)
				return
			}
		}
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

		// Cache lookup for the cross-repo aggregate. We skip the cache when
		// repo_id is set because that path is already cheap (filters down
		// to one repo's rows) and avoids worrying about per-user
		// invalidation. The cross-repo aggregate path is admin-only in
		// Phase 3 so all callers share the same response shape — safe to
		// share a cache key.
		var cacheStore cache.Store
		var cacheKey string
		var watermark time.Time
		if repoID == "" {
			cacheStore = cache.NewPostgresStore(db)
			watermark = unifiedDepsWatermark(r.Context(), db)
			cacheKey = unifiedDepsCacheKey(page, perPage, search, ecosystem, source, sortColumn, sortOrder)
			if entry, ok, _ := cache.GetJSON[unifiedDepsCacheEntry](r.Context(), cacheStore, cacheKey); ok {
				if !watermark.IsZero() && !entry.Watermark.Before(watermark) {
					w.Header().Set("Content-Type", "application/json")
					_ = json.NewEncoder(w).Encode(entry.Response)
					return
				}
			}
		}

		// Build the query. When a source filter is specified, short-circuit to avoid
		// scanning both sbom_component_view and manifest_dependencies unnecessarily.
		var query string
		args := []interface{}{}

		switch source {
		case "sbom":
			// Skip manifest_deps CTE entirely – only scan sbom_component_view.
			// LEFT JOIN on repo_commits so image-bound SBOM components survive
			// the join; repo_count counts only REPO_COMMIT-bound rows,
			// image_count only IMAGE_DIGEST-bound rows.
			query = `
				WITH sbom_deps AS (
					SELECT
						scv.name,
						scv.ecosystem,
						MIN(NULLIF(split_part(scv.purl, '@', 1), '')) as purl,
						COUNT(DISTINCT COALESCE(scv.version, NULLIF(scv.purl_version, ''), '')) as version_count,
						COUNT(DISTINCT scv.sbom_id) as sbom_count,
						COUNT(DISTINCT CASE WHEN scv.asset_type = 'REPO_COMMIT' THEN rc.repo_id END) as repo_count,
						COUNT(DISTINCT CASE WHEN scv.asset_type = 'IMAGE_DIGEST' THEN scv.asset_ref_id END) as image_count
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
					LEFT JOIN repo_commits rc ON rc.id = scv.asset_ref_id AND scv.asset_type = 'REPO_COMMIT'
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
				SELECT name, ecosystem, purl, 'sbom' AS sources, version_count, sbom_count, repo_count, image_count,
				       false AS has_direct, NULL::text[] AS scopes
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
				SELECT name, ecosystem, NULL AS purl, 'manifest' AS sources, version_count, 0 AS sbom_count, repo_count, 0 AS image_count,
				       has_direct, scopes
				FROM manifest_deps
			`

		default:
			// Both sources (or "both" filter) – FULL OUTER JOIN across all data.
			// LEFT JOIN on repo_commits so image-bound SBOM components survive
			// the join; repo_count counts only REPO_COMMIT-bound rows,
			// image_count only IMAGE_DIGEST-bound rows.
			query = `
				WITH sbom_deps AS (
					SELECT
						scv.name,
						scv.ecosystem,
						MIN(NULLIF(split_part(scv.purl, '@', 1), '')) as purl_base,
						'sbom' as source,
						COUNT(DISTINCT COALESCE(scv.version, NULLIF(scv.purl_version, ''), '')) as version_count,
						COUNT(DISTINCT scv.sbom_id) as sbom_count,
						COUNT(DISTINCT CASE WHEN scv.asset_type = 'REPO_COMMIT' THEN rc.repo_id END) as repo_count,
						COUNT(DISTINCT CASE WHEN scv.asset_type = 'IMAGE_DIGEST' THEN scv.asset_ref_id END) as image_count
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
					LEFT JOIN repo_commits rc ON rc.id = scv.asset_ref_id AND scv.asset_type = 'REPO_COMMIT'
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
						COALESCE(s.image_count, 0) as image_count,
						COALESCE(m.has_direct, false) as has_direct,
						m.scopes
					FROM sbom_deps s
					FULL OUTER JOIN manifest_deps m
						ON s.name = m.name
						AND s.ecosystem = m.ecosystem
				)
				SELECT name, ecosystem, purl, sources, version_count, sbom_count, repo_count, image_count, has_direct, scopes FROM merged
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

		// Pagination: ask for one row past the page so we can report
		// has_more without a second COUNT query. The extra row is
		// dropped before serialising.
		offset := (page - 1) * perPage
		query += ` LIMIT ? OFFSET ?`
		args = append(args, interface{}(perPage+1), interface{}(offset))

		rows, err := db.WithContext(r.Context()).Raw(query, args...).Rows()
		if err != nil {
			log.Printf("unified deps query error: %v", err)
			http.Error(w, "database error", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		deps := make([]UnifiedDependency, 0, perPage)
		for rows.Next() {
			var dep UnifiedDependency
			var sources string
			var purl sql.NullString
			var scopes interface{}

			if err := rows.Scan(
				&dep.Name, &dep.Ecosystem, &purl,
				&sources, &dep.VersionCount,
				&dep.SBOMCount, &dep.RepoCount, &dep.ImageCount,
				&dep.HasDirect, &scopes,
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
			if dep.ImageCount > 0 {
				// Surface 'image' as a secondary source so the UI badge row
				// can render a container icon alongside the primary source.
				dep.Sources = append(dep.Sources, "image")
			}
			deps = append(deps, dep)
		}

		hasMore := len(deps) > perPage
		if hasMore {
			deps = deps[:perPage]
		}

		resp := UnifiedDependenciesResponse{
			Dependencies: deps,
			Page:         page,
			PerPage:      perPage,
			HasMore:      hasMore,
		}

		if cacheStore != nil && cache.ShouldStore(r.Context()) {
			_ = cache.SetJSON(r.Context(), cacheStore, cacheKey, unifiedDepsCacheEntry{
				Watermark: watermark,
				Response:  resp,
			}, unifiedDepsCacheTTL)
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
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
	VulnCount int      `json:"vuln_count,omitempty"`
}

// DependencyAsset describes where a dependency is used (from SBOM or manifest)
type DependencyAsset struct {
	AssetType       string  `json:"asset_type"` // "REPO_COMMIT" or "IMAGE_DIGEST"
	RepoID          string  `json:"repo_id,omitempty"`
	Provider        string  `json:"provider,omitempty"`
	ProviderID      string  `json:"provider_id,omitempty"`
	ProviderBaseURL string  `json:"provider_base_url,omitempty"`
	Org             string  `json:"org,omitempty"`
	Slug            string  `json:"slug,omitempty"`
	CommitSHA       *string `json:"commit_sha,omitempty"`
	ImageID         string  `json:"image_id,omitempty"`
	ImageRegistry   string  `json:"image_registry,omitempty"`
	ImageRepository string  `json:"image_repository,omitempty"`
	ImageDigest     string  `json:"image_digest,omitempty"`
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
	GroupPath  string   `json:"group_path"`
	Name       string   `json:"name"`
	Ecosystem  string   `json:"ecosystem"`
	Version    string   `json:"version"`
	Sources    []string `json:"sources"`
	Direct     bool     `json:"direct"`
	OriginPath string   `json:"origin_path,omitempty"`
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

		// Scope filter: for non-admin / non-wildcard callers the CTEs
		// below restrict to repos and repo-backed images the caller
		// can read. For unrestricted callers the filter collapses to
		// TRUE so the aggregate is unchanged.
		readable, unrestricted, err := readableRepoIDSet(r, db)
		if err != nil {
			http.Error(w, "query failed", http.StatusInternalServerError)
			return
		}
		readableIDs := make([]string, 0, len(readable))
		for id := range readable {
			readableIDs = append(readableIDs, id)
		}
		sbomRepoFilter, sbomRepoArgs, sbomImageFilter, sbomImageArgs, manifestFilter, manifestArgs := dependencyACLFragments(unrestricted, readableIDs)

		// Aggregate versions from both SBOM (repo + image) and manifest sources.
		// purl_base is computed once in the sbom_versions CTE and projected via MIN() OVER ()
		// to avoid a second round-trip for the PURL lookup.
		versionsQuery := `
			WITH sbom_rows AS (
				SELECT
					COALESCE(s.version, NULLIF(s.purl_version, ''), '') as version,
					s.asset_type,
					s.asset_ref_id,
					NULLIF(split_part(s.purl, '@', 1), '') as purl_base,
					NULLIF(s.licenses, '') as licenses
				FROM sbom_component_view s
				WHERE s.is_root = false
				  AND s.purl IS NOT NULL
				  AND COALESCE(s.package_name, s.normalized_name, s.name) = ? AND s.kind = ?
				  AND (
				    s.asset_type NOT IN ('REPO_COMMIT','IMAGE_DIGEST')
				    OR (s.asset_type = 'REPO_COMMIT' AND ` + sbomRepoFilter + `)
				    OR (s.asset_type = 'IMAGE_DIGEST' AND ` + sbomImageFilter + `)
				  )
			),
			sbom_versions AS (
				SELECT
					version,
					COUNT(DISTINCT CASE WHEN asset_type = 'REPO_COMMIT' THEN asset_ref_id END) as repo_count,
					COUNT(DISTINCT CASE WHEN asset_type = 'IMAGE_DIGEST' THEN asset_ref_id END) as image_count,
					MIN(purl_base) as purl_base,
					MIN(licenses) as licenses,
					'sbom' as source
				FROM sbom_rows
				GROUP BY version
			),
			manifest_versions AS (
				SELECT
					md.version,
					COUNT(DISTINCT m.repo_id) as repo_count,
					0 as image_count,
					NULL::text as purl_base,
					NULL::text as licenses,
					'manifest' as source
				FROM manifest_dependencies md
				JOIN manifests m ON m.id = md.manifest_id
				WHERE md.name = ? AND md.ecosystem = ?
				  AND ` + manifestFilter + `
				GROUP BY md.version
			),
			merged_versions AS (
				SELECT
					COALESCE(s.version, m.version) as version,
					COALESCE(s.repo_count, 0) + COALESCE(m.repo_count, 0) as repo_count,
					COALESCE(s.image_count, 0) as image_count,
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
			SELECT version, repo_count, image_count, sources,
			       MIN(purl_base) OVER () AS overall_purl,
			       MIN(NULLIF(licenses, '')) OVER () AS overall_licenses
			FROM merged_versions
			ORDER BY (repo_count + image_count) DESC, version DESC
			LIMIT 100
		`

		args := []any{name, ecosystem}
		args = append(args, sbomRepoArgs...)
		args = append(args, sbomImageArgs...)
		args = append(args, name, ecosystem)
		args = append(args, manifestArgs...)
		rows, err := db.WithContext(r.Context()).Raw(versionsQuery, args...).Rows()
		if err != nil {
			http.Error(w, "query failed", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		versions := make([]DependencyVersionInfo, 0)
		totalRepoCount := 0
		totalImageCount := 0
		var overallPURL sql.NullString
		var overallLicenses sql.NullString
		for rows.Next() {
			var v DependencyVersionInfo
			var imageCount int
			var sources string
			if err := rows.Scan(&v.Version, &v.RepoCount, &imageCount, &sources, &overallPURL, &overallLicenses); err != nil {
				log.Printf("version scan error: %v", err)
				continue
			}
			v.Sources = []string{sources}
			versions = append(versions, v)
			totalRepoCount += v.RepoCount
			totalImageCount += imageCount
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

		versionNames := make([]string, 0, len(versions))
		for _, v := range versions {
			if v.Version != "" {
				versionNames = append(versionNames, v.Version)
			}
		}
		vulnCounts := vulnerabilities.CountByVersion(r.Context(), db, overallPURL.String, name, versionNames)
		for i := range versions {
			versions[i].VulnCount = vulnCounts[versions[i].Version]
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
			ImageCount:   totalImageCount,
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
						NULL::text as image_id,
						NULL::text as image_registry,
						NULL::text as image_repository,
						NULL::text as image_digest,
						COALESCE(s.version, NULLIF(s.purl_version, ''), '') as version,
						'sbom' as source,
						NULL::text as manifest_path,
						NULL::text as manifest_type,
						false as direct,
						NULL::text as scope,
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

			imageCTE := `
				image_assets AS (
					SELECT DISTINCT
						'IMAGE_DIGEST' as asset_type,
						NULL::text as repo_id,
						NULL::text as provider,
						NULL::text as org,
						NULL::text as slug,
						NULL::text as provider_instance_id,
						NULL::text as commit_sha,
						id.id::text as image_id,
						id.registry as image_registry,
						id.repository as image_repository,
						id.digest as image_digest,
						COALESCE(s.version, NULLIF(s.purl_version, ''), '') as version,
						'sbom' as source,
						NULL::text as manifest_path,
						NULL::text as manifest_type,
						false as direct,
						NULL::text as scope,
						sb.created_at
					FROM sbom_component_view s
					JOIN sbom_bindings sb ON sb.sbom_id = s.sbom_id
					  AND sb.asset_type = 'IMAGE_DIGEST'
					  AND sb.asset_ref_id = s.asset_ref_id
					JOIN image_digests id ON id.id = sb.asset_ref_id
					WHERE s.is_root = false
					  AND s.purl IS NOT NULL
					  AND s.kind = ?
					  AND COALESCE(s.package_name, s.normalized_name, s.name) = ?
			`
			args = append(args, ecosystem, name)
			if len(versions) > 0 {
				imageCTE += ` AND COALESCE(s.version, NULLIF(s.purl_version, ''), '') IN (` + inPlaceholders(len(versions)) + `)`
				for _, v := range versions {
					args = append(args, v)
				}
			}
			imageCTE += `
				)
			`
			cteParts = append(cteParts, imageCTE)
			selectParts = append(selectParts, `SELECT * FROM image_assets`)
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
						''::text as commit_sha,
						NULL::text as image_id,
						NULL::text as image_registry,
						NULL::text as image_repository,
						NULL::text as image_digest,
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
				COALESCE(ca.repo_id, '') as repo_id,
				COALESCE(pi.display_name, ca.provider, '') as provider,
				COALESCE(ca.provider_instance_id, '') as provider_id,
				COALESCE(ca.org, '') as org,
				COALESCE(ca.slug, '') as slug,
				ca.commit_sha,
				COALESCE(ca.image_id, '') as image_id,
				COALESCE(ca.image_registry, '') as image_registry,
				COALESCE(ca.image_repository, '') as image_repository,
				COALESCE(ca.image_digest, '') as image_digest,
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
				&commitSHA, &a.ImageID, &a.ImageRegistry, &a.ImageRepository, &a.ImageDigest,
				&a.Version, &a.Source, &manifestPath,
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
		if ok, err := canReadRepoByID(r, db, repoID); err != nil || !ok {
			notFoundOrForbidden(w)
			return
		}

		query := `
			WITH latest_repo_binding AS (
				SELECT sb.sbom_id, sb.asset_ref_id
				FROM sbom_bindings sb
				JOIN repo_commits rc ON rc.id = sb.asset_ref_id
				WHERE sb.asset_type = 'REPO_COMMIT'
				  AND rc.repo_id = ?
				ORDER BY rc.created_at DESC
				LIMIT 1
			),
			latest_sbom_json AS (
				SELECT
					lrb.sbom_id,
					convert_from(s.content_bytes, 'utf8')::jsonb AS doc
				FROM latest_repo_binding lrb
				JOIN sboms s ON s.id = lrb.sbom_id
			),
			sbom_component_paths AS (
				SELECT
					COALESCE(comp->>'bom-ref', comp->>'purl') AS component_ref,
					MAX(prop->>'value') FILTER (WHERE prop->>'name' = 'syft:location:0:path') AS origin_path
				FROM latest_sbom_json lsj
				JOIN LATERAL jsonb_array_elements(COALESCE(lsj.doc->'components', '[]'::jsonb)) comp ON TRUE
				LEFT JOIN LATERAL jsonb_array_elements(COALESCE(comp->'properties', '[]'::jsonb)) prop ON TRUE
				GROUP BY COALESCE(comp->>'bom-ref', comp->>'purl')
			),
			sbom_rows AS (
				SELECT DISTINCT
					COALESCE(s.package_name, s.normalized_name, s.name) AS name,
					s.kind AS ecosystem,
					COALESCE(s.version, NULLIF(s.purl_version, ''), '') AS version,
					scp.origin_path AS origin_path,
					false AS direct,
					'sbom' AS source
				FROM sbom_component_view s
				JOIN latest_repo_binding lrb ON lrb.sbom_id = s.sbom_id AND lrb.asset_ref_id = s.asset_ref_id
				LEFT JOIN sbom_component_paths scp ON scp.component_ref = s.component_ref
				WHERE s.asset_type = 'REPO_COMMIT'
				  AND s.is_root = false
				  AND s.purl IS NOT NULL
				  AND COALESCE(s.package_name, s.normalized_name, s.name) IS NOT NULL
			),
			manifest_rows AS (
				SELECT
					md.name,
					md.ecosystem,
					COALESCE(md.version, '') AS version,
					m.path AS origin_path,
					BOOL_OR(md.direct) AS direct,
					'manifest' AS source
				FROM manifest_dependencies md
				JOIN manifests m ON m.id = md.manifest_id
				WHERE m.repo_id = ?
				  AND md.name IS NOT NULL
				GROUP BY md.name, md.ecosystem, COALESCE(md.version, ''), m.path
			),
			rows AS (
				SELECT name, ecosystem, version, origin_path, direct, source FROM sbom_rows
				UNION ALL
				SELECT name, ecosystem, version, origin_path, direct, source FROM manifest_rows
			)
			SELECT
				name,
				ecosystem,
				version,
				origin_path,
				direct,
				source
			FROM rows
			ORDER BY
				LOWER(COALESCE(origin_path, '')) ASC,
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

		type repoDependencyKey struct {
			groupPath string
			name      string
			ecosystem string
			version   string
		}

		merged := make(map[repoDependencyKey]*RepoDependencyItem)
		for rows.Next() {
			var (
				name, ecosystem, version, source string
				direct                           bool
				originPath                       sql.NullString
			)
			if err := rows.Scan(&name, &ecosystem, &version, &originPath, &direct, &source); err != nil {
				log.Printf("repo dependencies scan error: %v", err)
				continue
			}

			rawOriginPath := cleanDependencyPath(originPath.String)
			groupPath := normalizeDependencyGroupPath(rawOriginPath)
			key := repoDependencyKey{
				groupPath: groupPath,
				name:      name,
				ecosystem: ecosystem,
				version:   version,
			}

			item, exists := merged[key]
			if !exists {
				item = &RepoDependencyItem{
					GroupPath:  groupPath,
					Name:       name,
					Ecosystem:  ecosystem,
					Version:    version,
					Direct:     direct,
					OriginPath: rawOriginPath,
					Sources:    []string{},
				}
				merged[key] = item
			}

			item.Direct = item.Direct || direct
			if item.OriginPath == "" && rawOriginPath != "" {
				item.OriginPath = rawOriginPath
			}
			if !containsString(item.Sources, source) {
				item.Sources = append(item.Sources, source)
			}
		}

		dependencies := make([]RepoDependencyItem, 0, len(merged))
		for _, item := range merged {
			sort.Strings(item.Sources)
			dependencies = append(dependencies, *item)
		}
		sort.Slice(dependencies, func(i, j int) bool {
			if dependencies[i].GroupPath != dependencies[j].GroupPath {
				return dependencies[i].GroupPath < dependencies[j].GroupPath
			}
			if dependencies[i].Direct != dependencies[j].Direct {
				return dependencies[i].Direct && !dependencies[j].Direct
			}
			if dependencies[i].Name != dependencies[j].Name {
				return strings.ToLower(dependencies[i].Name) < strings.ToLower(dependencies[j].Name)
			}
			return strings.ToLower(dependencies[i].Version) < strings.ToLower(dependencies[j].Version)
		})

		writeJSON(w, http.StatusOK, repoDependenciesResponse{
			Dependencies: dependencies,
			Total:        len(dependencies),
		})
	}
}

func normalizeDependencyGroupPath(path string) string {
	path = cleanDependencyPath(path)
	if path == "" {
		return "Scanner detected"
	}

	dir := filepath.ToSlash(filepath.Dir(path))
	base := filepath.Base(path)
	join := func(name string) string {
		if dir == "." || dir == "" {
			return name
		}
		return filepath.ToSlash(filepath.Join(dir, name))
	}

	switch base {
	case "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "bun.lock", "bun.lockb":
		return join("package.json")
	case "go.sum":
		return join("go.mod")
	case "Cargo.lock":
		return join("Cargo.toml")
	case "Gemfile.lock":
		return join("Gemfile")
	case "composer.lock":
		return join("composer.json")
	case "pubspec.lock":
		return join("pubspec.yaml")
	case "mix.lock":
		return join("mix.exs")
	case "Podfile.lock":
		return join("Podfile")
	case "Cartfile.resolved":
		return join("Cartfile")
	case "Manifest.toml":
		return join("Project.toml")
	case "poetry.lock":
		return join("pyproject.toml")
	case "Pipfile.lock":
		return join("Pipfile")
	default:
		return path
	}
}

func cleanDependencyPath(path string) string {
	path = filepath.ToSlash(strings.TrimSpace(path))
	path = strings.TrimPrefix(path, "./")
	path = strings.TrimLeft(path, "/")
	if path == "." {
		return ""
	}
	return path
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
