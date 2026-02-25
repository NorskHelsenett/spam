package uiapi

import (
	"net/http"
	"time"

	"github.com/NorskHelsenett/spam/internal/auth"
	"gorm.io/gorm"
)

type AppSummaryCounts struct {
	SBOMCount             int64 `json:"sbom_count"`
	RepoCount             int64 `json:"repo_count"`
	RepoWithSBOMCount     int64 `json:"repo_with_sbom_count"`
	ImageCount            int64 `json:"image_count"`
	ComponentCount        int64 `json:"component_count"`
	ComponentVersionCount int64 `json:"component_version_count"`
	LicenseCount          int64 `json:"license_count"`
	MissingLicenseCount   int64 `json:"missing_license_count"`
	SecretsCount          int64 `json:"secrets_count"`
}

type AppSummaryScanner struct {
	Name  string `json:"name"`
	Count int64  `json:"count"`
}

type AppSummarySBOM struct {
	SBOMID         string    `json:"sbom_id"`
	CreatedAt      time.Time `json:"created_at"`
	ScannerName    string    `json:"scanner_name"`
	ScannerVersion string    `json:"scanner_version"`
	AssetType      string    `json:"asset_type"`
	RepoName       string    `json:"repo_name,omitempty"`
	CommitSHA      string    `json:"commit_sha,omitempty"`
	ImageRegistry  string    `json:"image_registry,omitempty"`
	ImageRepo      string    `json:"image_repository,omitempty"`
	ImageDigest    string    `json:"image_digest,omitempty"`
	ComponentCount int64     `json:"component_count"`
}

type AppSummaryComponent struct {
	Kind         string `json:"kind"`
	PackageName  string `json:"package_name"`
	SBOMCount    int64  `json:"sbom_count"`
	VersionCount int64  `json:"version_count"`
}

type AppSummaryLicense struct {
	License string `json:"license"`
	Count   int64  `json:"count"`
}

type AppSummaryResponse struct {
	Counts        AppSummaryCounts      `json:"counts"`
	Scanners      []AppSummaryScanner   `json:"scanners"`
	RecentSBOMs   []AppSummarySBOM      `json:"recent_sboms"`
	TopComponents []AppSummaryComponent `json:"top_components"`
	TopLicenses   []AppSummaryLicense   `json:"top_licenses"`
}

// AppSummaryHandler returns dashboard metrics derived from SBOM views.
func AppSummaryHandler(db *gorm.DB, authService *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if requireAuth(w, r, authService) == nil {
			return
		}

		var resp AppSummaryResponse

		// Counts – scoped to the latest (bound) SBOM per asset.
		// Single-pass over sbom_component_view to avoid repeated full scans.
		if err := db.WithContext(r.Context()).Raw(`
			WITH comp_stats AS (
				SELECT
					COUNT(DISTINCT kind || ':' || package_name)
						FILTER (WHERE package_name IS NOT NULL)            AS component_count,
					COUNT(DISTINCT kind || ':' || package_name || '@' || COALESCE(purl_version, ''))
						FILTER (WHERE package_name IS NOT NULL)            AS component_version_count,
					COUNT(DISTINCT kind || ':' || package_name) FILTER (WHERE licenses IS NULL OR licenses = '') AS missing_license_count,
					COUNT(DISTINCT trim(lic)) FILTER (WHERE trim(lic) <> '') AS license_count
				FROM sbom_component_view c
				LEFT JOIN LATERAL unnest(string_to_array(c.licenses, ',')) AS lic ON TRUE
				WHERE c.type = 'library' AND c.asset_type IS NOT NULL
			),
			latest_repo_secrets AS (
				SELECT DISTINCT ON (repo_id)
					repo_id,
					finding_count
				FROM run_secrets
				WHERE repo_id IS NOT NULL AND repo_id <> ''
				ORDER BY repo_id, created_at DESC
			)
			SELECT
				(SELECT COUNT(*) FROM sbom_bindings) AS sbom_count,
				(SELECT COUNT(*) FROM repos) AS repo_count,
				(SELECT COUNT(DISTINCT m.repo_id) FROM sbom_metadata_view m INNER JOIN sbom_bindings sb ON sb.sbom_id = m.sbom_id WHERE m.repo_id IS NOT NULL) AS repo_with_sbom_count,
				(SELECT COUNT(*) FROM image_digests) AS image_count,
				cs.component_count,
				cs.component_version_count,
				cs.license_count,
				cs.missing_license_count,
				COALESCE((SELECT SUM(finding_count) FROM latest_repo_secrets), 0) AS secrets_count
			FROM comp_stats cs
		`).Scan(&resp.Counts).Error; err != nil {
			http.Error(w, "query failed", http.StatusInternalServerError)
			return
		}

		// Scanners
		if err := db.WithContext(r.Context()).Raw(`
			SELECT
				scanner_name AS name,
				COUNT(DISTINCT sbom_id) AS count
			FROM sbom_metadata_view
			WHERE scanner_name <> ''
			GROUP BY scanner_name
			ORDER BY count DESC, scanner_name ASC
		`).Scan(&resp.Scanners).Error; err != nil {
			http.Error(w, "query failed", http.StatusInternalServerError)
			return
		}

		// Recent SBOMs – join pre-aggregated library counts to avoid a correlated subquery per row.
		if err := db.WithContext(r.Context()).Raw(`
			SELECT
				m.sbom_id,
				m.created_at,
				m.scanner_name,
				m.scanner_version,
				m.asset_type,
				COALESCE(m.repo_name, '') AS repo_name,
				COALESCE(m.commit_sha, '') AS commit_sha,
				COALESCE(m.image_registry, '') AS image_registry,
				COALESCE(m.image_repository, '') AS image_repository,
				COALESCE(m.image_digest, '') AS image_digest,
				COALESCE(lib.component_count, 0) AS component_count
			FROM sbom_metadata_view m
			LEFT JOIN (
				SELECT sbom_id, COUNT(*) AS component_count
				FROM sbom_component_view
				WHERE type = 'library'
				GROUP BY sbom_id
			) lib ON lib.sbom_id = m.sbom_id
			ORDER BY m.created_at DESC
			LIMIT 8
		`).Scan(&resp.RecentSBOMs).Error; err != nil {
			http.Error(w, "query failed", http.StatusInternalServerError)
			return
		}

		// Top components by SBOM count
		if err := db.WithContext(r.Context()).Raw(`
			SELECT
				kind,
				package_name,
				COUNT(DISTINCT sbom_id) AS sbom_count,
				COUNT(DISTINCT purl_version) AS version_count
			FROM sbom_component_view
			WHERE type = 'library' AND package_name IS NOT NULL
			GROUP BY kind, package_name
			ORDER BY sbom_count DESC, package_name ASC
			LIMIT 10
		`).Scan(&resp.TopComponents).Error; err != nil {
			http.Error(w, "query failed", http.StatusInternalServerError)
			return
		}

		// Top licenses – scoped to current SBOMs only
		if err := db.WithContext(r.Context()).Raw(`
			WITH license_items AS (
				SELECT trim(lic) AS license
				FROM sbom_component_view c
				LEFT JOIN LATERAL unnest(string_to_array(COALESCE(c.licenses, ''), ',')) AS lic ON TRUE
				WHERE c.licenses IS NOT NULL AND c.licenses <> '' AND c.asset_type IS NOT NULL
			)
			SELECT license, COUNT(*) AS count
			FROM license_items
			WHERE license <> ''
			GROUP BY license
			ORDER BY count DESC, license ASC
			LIMIT 10
		`).Scan(&resp.TopLicenses).Error; err != nil {
			http.Error(w, "query failed", http.StatusInternalServerError)
			return
		}

		writeJSON(w, http.StatusOK, resp)
	}
}
