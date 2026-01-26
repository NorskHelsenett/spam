package uiapi

import (
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/NorskHelsenett/spam/internal/auth"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

const (
	defaultPageSize = 50
	maxPageSize     = 200
)

// ComponentSummary is the API response for a component.
type ComponentSummary struct {
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	Ecosystem    string    `json:"ecosystem"`
	PURL         string    `json:"purl,omitempty"`
	VersionCount int       `json:"version_count"`
	RepoCount    int       `json:"repo_count"`
	ImageCount   int       `json:"image_count"`
	CreatedAt    time.Time `json:"created_at"`
}

// ComponentDetail includes versions for a single component.
type ComponentDetail struct {
	ComponentSummary
	Versions []VersionSummary `json:"versions"`
}

// VersionSummary describes a component version.
type VersionSummary struct {
	ID        string    `json:"id"`
	Version   string    `json:"version"`
	RepoCount int       `json:"repo_count"`
	CreatedAt time.Time `json:"created_at"`
}

// ComponentAsset describes where a component is used.
type ComponentAsset struct {
	AssetType       string    `json:"asset_type"`
	RepoID          string    `json:"repo_id,omitempty"`
	Provider        string    `json:"provider,omitempty"`
	Org             string    `json:"org,omitempty"`
	Slug            string    `json:"slug,omitempty"`
	CommitSHA       string    `json:"commit_sha,omitempty"`
	ImageRegistry   string    `json:"image_registry,omitempty"`
	ImageRepository string    `json:"image_repository,omitempty"`
	ImageDigest     string    `json:"image_digest,omitempty"`
	Version         string    `json:"version"`
	SBOMID          string    `json:"sbom_id"`
	BoundAt         time.Time `json:"bound_at"`
}

type componentListResponse struct {
	Components []ComponentSummary `json:"components"`
	Total      int64              `json:"total"`
	Page       int                `json:"page"`
	PageSize   int                `json:"page_size"`
}

type componentAssetsResponse struct {
	Assets   []ComponentAsset `json:"assets"`
	Total    int64            `json:"total"`
	Page     int              `json:"page"`
	PageSize int              `json:"page_size"`
}

// ComponentsListHandler returns paginated components with search.
func ComponentsListHandler(db *gorm.DB, authService *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, err := authService.LoadSession(r); err != nil {
			http.Error(w, "unauthenticated", http.StatusUnauthorized)
			return
		}

		query := strings.TrimSpace(r.URL.Query().Get("q"))
		ecosystem := strings.TrimSpace(r.URL.Query().Get("ecosystem"))
		page, pageSize := parsePagination(r)

		var total int64
		countQuery := db.WithContext(r.Context()).Table("components")
		if query != "" {
			pattern := "%" + query + "%"
			countQuery = countQuery.Where("name ILIKE ? OR purl ILIKE ?", pattern, pattern)
		}
		if ecosystem != "" {
			countQuery = countQuery.Where("ecosystem = ?", ecosystem)
		}
		if err := countQuery.Count(&total).Error; err != nil {
			http.Error(w, "query failed", http.StatusInternalServerError)
			return
		}

		// Query components with aggregated counts
		rows, err := db.WithContext(r.Context()).Raw(`
			SELECT
				c.id,
				c.name,
				c.ecosystem,
				c.purl,
				c.created_at,
				COUNT(DISTINCT cv.id) as version_count,
				COUNT(DISTINCT CASE WHEN sb.asset_type = 'REPO_COMMIT' THEN sb.asset_ref_id END) as repo_count,
				COUNT(DISTINCT CASE WHEN sb.asset_type = 'IMAGE_DIGEST' THEN sb.asset_ref_id END) as image_count
			FROM components c
			LEFT JOIN component_versions cv ON cv.component_id = c.id
			LEFT JOIN sbom_components sc ON sc.component_version_id = cv.id
			LEFT JOIN sbom_bindings sb ON sb.sbom_id = sc.sbom_id
			WHERE (? = '' OR c.name ILIKE ? OR c.purl ILIKE ?)
			  AND (? = '' OR c.ecosystem = ?)
			GROUP BY c.id
			ORDER BY c.name ASC
			LIMIT ? OFFSET ?
		`, query, "%"+query+"%", "%"+query+"%", ecosystem, ecosystem, pageSize, (page-1)*pageSize).Rows()
		if err != nil {
			http.Error(w, "query failed", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		components := make([]ComponentSummary, 0)
		for rows.Next() {
			var c ComponentSummary
			if err := rows.Scan(&c.ID, &c.Name, &c.Ecosystem, &c.PURL, &c.CreatedAt, &c.VersionCount, &c.RepoCount, &c.ImageCount); err != nil {
				log.Printf("components list scan error: %v", err)
				continue
			}
			components = append(components, c)
		}

		writeJSON(w, http.StatusOK, componentListResponse{
			Components: components,
			Total:      total,
			Page:       page,
			PageSize:   pageSize,
		})
	}
}

// ComponentDetailHandler returns a single component with its versions.
func ComponentDetailHandler(db *gorm.DB, authService *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, err := authService.LoadSession(r); err != nil {
			http.Error(w, "unauthenticated", http.StatusUnauthorized)
			return
		}

		componentID := r.PathValue("componentID")
		if componentID == "" {
			http.Error(w, "component id required", http.StatusBadRequest)
			return
		}
		if !isValidUUID(componentID) {
			http.Error(w, "invalid component id format", http.StatusBadRequest)
			return
		}

		// Get component with counts
		row := db.WithContext(r.Context()).Raw(`
			SELECT
				c.id,
				c.name,
				c.ecosystem,
				c.purl,
				c.created_at,
				COUNT(DISTINCT cv.id) as version_count,
				COUNT(DISTINCT CASE WHEN sb.asset_type = 'REPO_COMMIT' THEN sb.asset_ref_id END) as repo_count,
				COUNT(DISTINCT CASE WHEN sb.asset_type = 'IMAGE_DIGEST' THEN sb.asset_ref_id END) as image_count
			FROM components c
			LEFT JOIN component_versions cv ON cv.component_id = c.id
			LEFT JOIN sbom_components sc ON sc.component_version_id = cv.id
			LEFT JOIN sbom_bindings sb ON sb.sbom_id = sc.sbom_id
			WHERE c.id = ?
			GROUP BY c.id
		`, componentID).Row()

		var detail ComponentDetail
		if err := row.Scan(&detail.ID, &detail.Name, &detail.Ecosystem, &detail.PURL, &detail.CreatedAt, &detail.VersionCount, &detail.RepoCount, &detail.ImageCount); err != nil {
			if err.Error() == "sql: no rows in result set" {
				http.Error(w, "component not found", http.StatusNotFound)
				return
			}
			http.Error(w, "query failed", http.StatusInternalServerError)
			return
		}

		// Get versions with repo counts
		versionRows, err := db.WithContext(r.Context()).Raw(`
			SELECT
				cv.id,
				cv.version,
				cv.created_at,
				COUNT(DISTINCT sb.asset_ref_id) as repo_count
			FROM component_versions cv
			LEFT JOIN sbom_components sc ON sc.component_version_id = cv.id
			LEFT JOIN sbom_bindings sb ON sb.sbom_id = sc.sbom_id
			WHERE cv.component_id = ?
			GROUP BY cv.id
			ORDER BY cv.version DESC
			LIMIT 100
		`, componentID).Rows()
		if err != nil {
			http.Error(w, "query failed", http.StatusInternalServerError)
			return
		}
		defer versionRows.Close()

		detail.Versions = make([]VersionSummary, 0)
		for versionRows.Next() {
			var v VersionSummary
			if err := versionRows.Scan(&v.ID, &v.Version, &v.CreatedAt, &v.RepoCount); err != nil {
				log.Printf("component versions scan error: %v", err)
				continue
			}
			detail.Versions = append(detail.Versions, v)
		}

		writeJSON(w, http.StatusOK, detail)
	}
}

// ComponentAssetsHandler returns repos/images containing a component.
func ComponentAssetsHandler(db *gorm.DB, authService *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, err := authService.LoadSession(r); err != nil {
			http.Error(w, "unauthenticated", http.StatusUnauthorized)
			return
		}

		componentID := r.PathValue("componentID")
		if componentID == "" {
			http.Error(w, "component id required", http.StatusBadRequest)
			return
		}
		if !isValidUUID(componentID) {
			http.Error(w, "invalid component id format", http.StatusBadRequest)
			return
		}

		version := strings.TrimSpace(r.URL.Query().Get("version"))
		page, pageSize := parsePagination(r)

		// Count total
		countQuery := db.WithContext(r.Context()).Raw(`
			SELECT COUNT(DISTINCT sb.id)
			FROM sbom_bindings sb
			JOIN sbom_components sc ON sc.sbom_id = sb.sbom_id
			JOIN component_versions cv ON cv.id = sc.component_version_id
			WHERE cv.component_id = ?
			  AND (? = '' OR cv.version = ?)
		`, componentID, version, version)

		var total int64
		if err := countQuery.Row().Scan(&total); err != nil {
			http.Error(w, "query failed", http.StatusInternalServerError)
			return
		}

		// Query assets
		rows, err := db.WithContext(r.Context()).Raw(`
			SELECT
				sb.asset_type,
				COALESCE(r.id, '') as repo_id,
				COALESCE(r.provider, '') as provider,
				COALESCE(r.org, '') as org,
				COALESCE(r.slug, '') as slug,
				COALESCE(rc.commit_sha, '') as commit_sha,
				COALESCE(img.registry, '') as image_registry,
				COALESCE(img.repository, '') as image_repository,
				COALESCE(img.digest, '') as image_digest,
				cv.version,
				sb.sbom_id,
				sb.created_at
			FROM sbom_bindings sb
			JOIN sbom_components sc ON sc.sbom_id = sb.sbom_id
			JOIN component_versions cv ON cv.id = sc.component_version_id
			LEFT JOIN repo_commits rc ON sb.asset_type = 'REPO_COMMIT' AND rc.id = sb.asset_ref_id
			LEFT JOIN repos r ON r.id = rc.repo_id
			LEFT JOIN image_digests img ON sb.asset_type = 'IMAGE_DIGEST' AND img.id = sb.asset_ref_id
			WHERE cv.component_id = ?
			  AND (? = '' OR cv.version = ?)
			ORDER BY sb.created_at DESC
			LIMIT ? OFFSET ?
		`, componentID, version, version, pageSize, (page-1)*pageSize).Rows()
		if err != nil {
			http.Error(w, "query failed", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		assets := make([]ComponentAsset, 0)
		for rows.Next() {
			var a ComponentAsset
			if err := rows.Scan(
				&a.AssetType, &a.RepoID, &a.Provider, &a.Org, &a.Slug, &a.CommitSHA,
				&a.ImageRegistry, &a.ImageRepository, &a.ImageDigest,
				&a.Version, &a.SBOMID, &a.BoundAt,
			); err != nil {
				log.Printf("component assets scan error: %v", err)
				continue
			}
			assets = append(assets, a)
		}

		writeJSON(w, http.StatusOK, componentAssetsResponse{
			Assets:   assets,
			Total:    total,
			Page:     page,
			PageSize: pageSize,
		})
	}
}

// EcosystemsListHandler returns distinct ecosystems.
func EcosystemsListHandler(db *gorm.DB, authService *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, err := authService.LoadSession(r); err != nil {
			http.Error(w, "unauthenticated", http.StatusUnauthorized)
			return
		}

		var ecosystems []string
		if err := db.WithContext(r.Context()).
			Table("components").
			Distinct("ecosystem").
			Where("ecosystem IS NOT NULL AND ecosystem != ''").
			Order("ecosystem ASC").
			Pluck("ecosystem", &ecosystems).Error; err != nil {
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
