package uiapi

import (
	"encoding/json"
	"log"
	"net/http"
	"strconv"

	"github.com/NorskHelsenett/spam/internal/auth"
	"gorm.io/gorm"
)

// UnifiedDependency combines data from SBOMs and manifests
type UnifiedDependency struct {
	Name      string   `json:"name"`
	Version   string   `json:"version"`
	Ecosystem string   `json:"ecosystem"`
	PURL      string   `json:"purl,omitempty"`
	Sources   []string `json:"sources"`          // ["sbom", "manifest", "both"]
	Direct    *bool    `json:"direct,omitempty"` // nil if unknown
	Scope     string   `json:"scope,omitempty"`
	SBOMCount int      `json:"sbom_count"` // How many SBOMs contain this
	RepoCount int      `json:"repo_count"` // How many repos use this
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

		// Build unified query
		query := `
			WITH sbom_deps AS (
				SELECT 
					c.name,
					cv.version,
					c.ecosystem,
					c.purl,
					'sbom' as source,
					COUNT(DISTINCT sc.sbom_id) as sbom_count,
					COUNT(DISTINCT sb.asset_ref_id) as repo_count
				FROM components c
				JOIN component_versions cv ON cv.component_id = c.id
				JOIN sbom_components sc ON sc.component_version_id = cv.id
				LEFT JOIN sbom_bindings sb ON sb.sbom_id = sc.sbom_id
				WHERE 1=1
		`

		args := []interface{}{}
		argIdx := 1

		if search != "" {
			query += ` AND c.name ILIKE $` + strconv.Itoa(argIdx)
			args = append(args, "%"+search+"%")
			argIdx++
		}
		if ecosystem != "" {
			query += ` AND c.ecosystem = $` + strconv.Itoa(argIdx)
			args = append(args, ecosystem)
			argIdx++
		}
		if repoID != "" {
			query += ` AND sb.asset_ref_id = $` + strconv.Itoa(argIdx)
			args = append(args, repoID)
			argIdx++
		}

		query += `
				GROUP BY c.name, cv.version, c.ecosystem, c.purl
			),
			manifest_deps AS (
				SELECT 
					md.name,
					md.version,
					md.ecosystem,
					NULL as purl,
					'manifest' as source,
					md.direct,
					md.scope,
					COUNT(DISTINCT m.id) as manifest_count,
					COUNT(DISTINCT m.repo_id) as repo_count
				FROM manifest_dependencies md
				JOIN manifests m ON m.id = md.manifest_id
				WHERE 1=1
		`

		// Reapply filters for manifest side
		if search != "" {
			query += ` AND md.name ILIKE $` + strconv.Itoa(argIdx)
			args = append(args, "%"+search+"%")
			argIdx++
		}
		if ecosystem != "" {
			query += ` AND md.ecosystem = $` + strconv.Itoa(argIdx)
			args = append(args, ecosystem)
			argIdx++
		}
		if repoID != "" {
			query += ` AND m.repo_id = $` + strconv.Itoa(argIdx)
			args = append(args, repoID)
			argIdx++
		}

		query += `
				GROUP BY md.name, md.version, md.ecosystem, md.direct, md.scope
			),
			merged AS (
				SELECT 
					COALESCE(s.name, m.name) as name,
					COALESCE(s.version, m.version) as version,
					COALESCE(s.ecosystem, m.ecosystem) as ecosystem,
					s.purl,
					CASE 
						WHEN s.name IS NOT NULL AND m.name IS NOT NULL THEN 'both'
						WHEN s.name IS NOT NULL THEN 'sbom'
						ELSE 'manifest'
					END as sources,
					m.direct,
					m.scope,
					COALESCE(s.sbom_count, 0) as sbom_count,
					COALESCE(s.repo_count, m.repo_count, 0) as repo_count
				FROM sbom_deps s
				FULL OUTER JOIN manifest_deps m 
					ON s.name = m.name 
					AND s.version = m.version 
					AND s.ecosystem = m.ecosystem
			)
			SELECT name, version, ecosystem, purl, sources, direct, scope, sbom_count, repo_count FROM merged
		`

		// Apply source filter if specified
		if source != "" {
			query += ` WHERE sources = $` + strconv.Itoa(argIdx)
			args = append(args, source)
			argIdx++
		}

		query += ` ORDER BY repo_count DESC, name ASC`

		// Count total
		countQuery := `SELECT COUNT(*) FROM (` + query + `) t`
		var total int64
		if err := db.WithContext(r.Context()).Raw(countQuery, args...).Scan(&total).Error; err != nil {
			log.Printf("unified deps count error: %v", err)
			http.Error(w, "database error", http.StatusInternalServerError)
			return
		}

		// Apply pagination
		offset := (page - 1) * perPage
		query += ` LIMIT $` + strconv.Itoa(argIdx) + ` OFFSET $` + strconv.Itoa(argIdx+1)
		args = append(args, perPage, offset)

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
			if err := rows.Scan(
				&dep.Name, &dep.Version, &dep.Ecosystem, &dep.PURL,
				&sources, &dep.Direct, &dep.Scope,
				&dep.SBOMCount, &dep.RepoCount,
			); err != nil {
				log.Printf("scan error: %v", err)
				continue
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
