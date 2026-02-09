package uiapi

import (
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"strconv"

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

		// Build unified query - group by name+ecosystem
		query := `
			WITH sbom_deps AS (
				SELECT
					scv.name,
					scv.ecosystem,
					MIN(NULLIF(split_part(scv.purl, '@', 1), '')) as purl_base,
					'sbom' as source,
					COUNT(DISTINCT COALESCE(scv.version, NULLIF(scv.purl_version, ''), '')) as version_count,
					COUNT(DISTINCT scv.sbom_id) as sbom_count,
					COUNT(DISTINCT CASE WHEN scv.asset_type = 'REPO_COMMIT' THEN scv.asset_ref_id END) as repo_count
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
				WHERE scv.name IS NOT NULL
		`

		args := []interface{}{}

		if search != "" {
			query += ` AND (scv.name ILIKE ? OR scv.purl ILIKE ?)`
			args = append(args, "%"+search+"%", "%"+search+"%")
		}
		if ecosystem != "" {
			query += ` AND scv.ecosystem = ?`
			args = append(args, ecosystem)
		}
		if repoID != "" {
			query += ` AND scv.asset_ref_id = ?`
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

		// Apply filters for manifest side (continue parameter numbering)
		if search != "" {
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
			SELECT name, ecosystem, purl, sources, version_count, sbom_count, repo_count, has_direct, scopes FROM merged
		`

		// Apply source filter if specified
		if source != "" {
			query += ` WHERE sources = ?`
			args = append(args, source)
		}

		// Apply sorting
		if sortOrder == "desc" {
			query += ` ORDER BY ` + sqlSortColumn + ` DESC`
		} else {
			query += ` ORDER BY ` + sqlSortColumn + ` ASC`
		}
		// Secondary sort by name for consistency
		query += `, name ASC`

		// Count total (before adding pagination to query/args)
		countQuery := `SELECT COUNT(*) FROM (` + query + `) t`
		var total int64
		if err := db.WithContext(r.Context()).Raw(countQuery, args...).Scan(&total).Error; err != nil {
			log.Printf("unified deps count error: %v", err)
			http.Error(w, "database error", http.StatusInternalServerError)
			return
		}

		// Apply pagination
		offset := (page - 1) * perPage
		query += ` LIMIT ? OFFSET ?`
		args = append(args, interface{}(perPage), interface{}(offset))

		// Execute query
		rows, err := db.WithContext(r.Context()).Raw(query, args...).Rows()
		if err != nil {
			log.Printf("unified deps query error: %v", err)
			http.Error(w, "database error", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

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
}

// DependencyVersionInfo describes a specific version of a dependency
type DependencyVersionInfo struct {
	Version   string   `json:"version"`
	RepoCount int      `json:"repo_count"`
	Sources   []string `json:"sources"` // "sbom", "manifest", or both
}

// DependencyAsset describes where a dependency is used (from SBOM or manifest)
type DependencyAsset struct {
	AssetType    string  `json:"asset_type"` // "REPO_COMMIT" only for now
	RepoID       string  `json:"repo_id,omitempty"`
	Provider     string  `json:"provider,omitempty"`
	Org          string  `json:"org,omitempty"`
	Slug         string  `json:"slug,omitempty"`
	CommitSHA    *string `json:"commit_sha,omitempty"`
	Version      string  `json:"version"`
	Source       string  `json:"source"` // "sbom" or "manifest"
	ManifestPath *string `json:"manifest_path,omitempty"`
	ManifestType *string `json:"manifest_type,omitempty"`
	Direct       bool    `json:"direct,omitempty"`
	Scope        *string `json:"scope,omitempty"`
}

type dependencyAssetsResponse struct {
	Assets   []DependencyAsset `json:"assets"`
	Total    int64             `json:"total"`
	Page     int               `json:"page"`
	PageSize int               `json:"page_size"`
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

		// Aggregate versions from both SBOM and manifest sources
		// For SBOMs: find all SBOMs containing this dependency, then count bound assets
		versionsQuery := `
			WITH sbom_versions AS (
				SELECT 
					COALESCE(s.version, NULLIF(s.purl_version, ''), '') as version,
					COUNT(DISTINCT s.asset_ref_id) as repo_count,
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
					END as sources
				FROM sbom_versions s
				FULL OUTER JOIN manifest_versions m ON s.version = m.version
			)
			SELECT version, repo_count, sources
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
		for rows.Next() {
			var v DependencyVersionInfo
			var sources string
			if err := rows.Scan(&v.Version, &v.RepoCount, &sources); err != nil {
				log.Printf("version scan error: %v", err)
				continue
			}
			v.Sources = []string{sources}
			versions = append(versions, v)
			if v.RepoCount > totalRepoCount {
				totalRepoCount = v.RepoCount
			}
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

		// Get PURL if available (for display)
		var purl sql.NullString
		db.WithContext(r.Context()).Raw(`
			SELECT MIN(NULLIF(split_part(s.purl, '@', 1), ''))
			FROM sbom_component_view s
			WHERE s.is_root = false
			  AND s.purl IS NOT NULL
			  AND COALESCE(s.package_name, s.normalized_name, s.name) = ? AND s.kind = ?
		`, name, ecosystem).Row().Scan(&purl)

		detail := DependencyDetail{
			Name:         name,
			Ecosystem:    ecosystem,
			PURL:         purl.String,
			VersionCount: len(versions),
			RepoCount:    totalRepoCount,
			ImageCount:   0, // Images only from SBOMs, we can calculate this if needed
			Sources:      sources,
			Versions:     versions,
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
		version := r.URL.Query().Get("version")

		if name == "" || ecosystem == "" {
			http.Error(w, "name and ecosystem required", http.StatusBadRequest)
			return
		}

		page, _ := strconv.Atoi(r.URL.Query().Get("page"))
		if page < 1 {
			page = 1
		}
		pageSize, _ := strconv.Atoi(r.URL.Query().Get("page_size"))
		if pageSize < 1 || pageSize > 200 {
			pageSize = 100
		}

		// Query assets from both SBOM and manifest sources
		// Simplified approach: find SBOMs containing this dependency, then find bound assets
		assetsQuery := `
			WITH sbom_assets AS (
				SELECT DISTINCT
					'REPO_COMMIT' as asset_type,
					r.id as repo_id,
					r.provider,
					r.org,
					r.slug,
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
				  AND COALESCE(s.package_name, s.normalized_name, s.name) = ? AND s.kind = ?
				  AND (? = '' OR COALESCE(s.version, NULLIF(s.purl_version, ''), '') = ?)
			),
			manifest_assets AS (
				SELECT 
					'REPO_COMMIT' as asset_type,
					r.id as repo_id,
					r.provider,
					r.org,
					r.slug,
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
				WHERE md.name = ? AND md.ecosystem = ?
				  AND (? = '' OR md.version = ?)
			),
			combined_assets AS (
				SELECT * FROM sbom_assets
				UNION ALL
				SELECT * FROM manifest_assets
			)
			SELECT 
				asset_type, repo_id, provider, org, slug, commit_sha,
				version, source, manifest_path, manifest_type, direct, scope
			FROM combined_assets
			ORDER BY created_at DESC
		`

		// Count total - simpler: count SBOMs with this dependency, then count bound assets
		countQuery := `
			WITH sbom_assets AS (
				SELECT DISTINCT sb.id
				FROM sbom_component_view s
				JOIN sbom_bindings sb ON sb.sbom_id = s.sbom_id
				  AND sb.asset_type = 'REPO_COMMIT'
				  AND sb.asset_ref_id = s.asset_ref_id
				WHERE s.is_root = false
				  AND s.purl IS NOT NULL
				  AND COALESCE(s.package_name, s.normalized_name, s.name) = ? AND s.kind = ?
				  AND (? = '' OR COALESCE(s.version, NULLIF(s.purl_version, ''), '') = ?)
			),
			manifest_assets AS (
				SELECT md.id
				FROM manifest_dependencies md
				WHERE md.name = ? AND md.ecosystem = ?
				  AND (? = '' OR md.version = ?)
			)
			SELECT (SELECT COUNT(*) FROM sbom_assets) + (SELECT COUNT(*) FROM manifest_assets)
		`

		var total int64
		if err := db.WithContext(r.Context()).Raw(countQuery, name, ecosystem, version, version, name, ecosystem, version, version).Scan(&total).Error; err != nil {
			http.Error(w, "query failed", http.StatusInternalServerError)
			return
		}

		// Apply pagination
		assetsQuery += ` LIMIT ? OFFSET ?`
		rows, err := db.WithContext(r.Context()).Raw(
			assetsQuery,
			name, ecosystem, version, version,
			name, ecosystem, version, version,
			pageSize, (page-1)*pageSize,
		).Rows()
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
				&a.AssetType, &a.RepoID, &a.Provider, &a.Org, &a.Slug,
				&commitSHA, &a.Version, &a.Source, &manifestPath,
				&manifestType, &a.Direct, &scope,
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
