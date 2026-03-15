package uiapi

import (
	"context"
	"log"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/NorskHelsenett/spam/internal/auth"
	"github.com/NorskHelsenett/spam/internal/cache"
	"github.com/NorskHelsenett/spam/internal/vulnerabilities"
	"gorm.io/gorm"
)

// appSummaryCacheTTL is long because the cache is version-gated by the
// materialized view refresh timestamp — not by wall-clock expiry.
const appSummaryCacheTTL = 24 * time.Hour
const appSummaryCacheKey = "app:summary:v2"

type AppSummaryCounts struct {
	SBOMCount             int64 `json:"sbom_count"`
	RepoCount             int64 `json:"repo_count"`
	RepoWithSBOMCount     int64 `json:"repo_with_sbom_count"`
	ImageCount            int64 `json:"image_count"`
	ComponentCount        int64 `json:"component_count"`
	ComponentVersionCount int64 `json:"component_version_count"`
	OSVPURLCount          int64 `json:"osv_purl_count"`
	OSVSBOMPURLCount      int64 `json:"osv_sbom_purl_count"`
	OSVManifestPURLCount  int64 `json:"osv_manifest_purl_count"`
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
	RepoID         string    `json:"repo_id,omitempty"`
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

// appSummaryCacheEntry wraps the response with the materialized view version
// so we can detect when the view has been refreshed and the cache is stale.
type appSummaryCacheEntry struct {
	ViewRefreshedAt time.Time          `json:"view_refreshed_at"`
	Response        AppSummaryResponse `json:"response"`
}

// appSummaryRefreshing guards against concurrent background refreshes.
var appSummaryRefreshing atomic.Bool

// AppSummaryHandler returns dashboard metrics derived from SBOM views.
// The response is cached until the materialized view is refreshed. When the
// view has been refreshed since the last cache write, stale data is returned
// immediately and the cache is updated in the background.
func AppSummaryHandler(db *gorm.DB, authService *auth.Service, c cache.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if requireAuth(w, r, authService) == nil {
			return
		}

		watermark := appSummaryWatermark(r.Context(), db)

		if entry, ok, _ := cache.GetJSON[appSummaryCacheEntry](r.Context(), c, appSummaryCacheKey); ok {
			if !watermark.IsZero() && !entry.ViewRefreshedAt.Before(watermark) {
				// Cache is current with the materialized view.
				writeJSON(w, http.StatusOK, entry.Response)
				return
			}
			// Stale: serve immediately, refresh in background.
			writeJSON(w, http.StatusOK, entry.Response)
			go func() {
				if !appSummaryRefreshing.CompareAndSwap(false, true) {
					return
				}
				defer appSummaryRefreshing.Store(false)
				ctx := context.Background()
				resp, err := computeAppSummary(ctx, db)
				if err != nil {
					log.Printf("app summary background refresh: %v", err)
					return
				}
				_ = maybeStoreAppSummary(ctx, c, watermark, resp)
			}()
			return
		}

		// Cache miss: compute synchronously.
		resp, err := computeAppSummary(r.Context(), db)
		if err != nil {
			http.Error(w, "query failed", http.StatusInternalServerError)
			return
		}
		_ = maybeStoreAppSummary(r.Context(), c, watermark, resp)
		writeJSON(w, http.StatusOK, resp)
	}
}

func maybeStoreAppSummary(ctx context.Context, c cache.Store, watermark time.Time, resp AppSummaryResponse) error {
	if !cache.ShouldStore(ctx) {
		return nil
	}
	return cache.SetJSON(ctx, c, appSummaryCacheKey, appSummaryCacheEntry{
		ViewRefreshedAt: watermark,
		Response:        resp,
	}, appSummaryCacheTTL)
}

func appSummaryWatermark(ctx context.Context, db *gorm.DB) time.Time {
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

func computeAppSummary(ctx context.Context, db *gorm.DB) (AppSummaryResponse, error) {
	var resp AppSummaryResponse

	// Counts – scoped to the latest (bound) SBOM per asset.
	// Single-pass over sbom_component_view to avoid repeated full scans.
	if err := db.WithContext(ctx).Raw(`
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
				findings
			FROM run_secrets
			WHERE repo_id IS NOT NULL AND repo_id <> ''
			ORDER BY repo_id, created_at DESC
		),
		latest_repo_secret_findings AS (
			SELECT DISTINCT
				COALESCE(
					NULLIF(finding ->> 'Fingerprint', ''),
					md5(
						concat_ws(
							'|',
							COALESCE(finding ->> 'RuleID', ''),
							COALESCE(finding ->> 'Description', ''),
							COALESCE(finding ->> 'File', ''),
							COALESCE(finding ->> 'StartLine', ''),
							COALESCE(finding ->> 'Match', ''),
							COALESCE(finding ->> 'Secret', '')
						)
					)
				) AS dedupe_key
			FROM latest_repo_secrets rs
			CROSS JOIN LATERAL jsonb_array_elements(COALESCE(rs.findings, '[]'::jsonb)) AS finding
		)
		SELECT
			(SELECT COUNT(*) FROM sbom_bindings) AS sbom_count,
			(SELECT COUNT(*) FROM repos) AS repo_count,
			(SELECT COUNT(DISTINCT repo_id) FROM sbom_metadata_view WHERE repo_id IS NOT NULL) AS repo_with_sbom_count,
			(SELECT COUNT(*) FROM image_digests) AS image_count,
			cs.component_count,
			cs.component_version_count,
			cs.license_count,
			cs.missing_license_count,
			COALESCE((SELECT COUNT(*) FROM latest_repo_secret_findings), 0) AS secrets_count
		FROM comp_stats cs
	`).Scan(&resp.Counts).Error; err != nil {
		return resp, err
	}

	purls, purlStats, err := vulnerabilities.CollectBatchPURLs(ctx, db)
	if err != nil {
		return resp, err
	}
	resp.Counts.OSVPURLCount = int64(len(purls))
	resp.Counts.OSVSBOMPURLCount = int64(purlStats.SBOMDistinct)
	resp.Counts.OSVManifestPURLCount = int64(purlStats.ManifestAdded)

	// Scanners
	if err := db.WithContext(ctx).Raw(`
		SELECT
			scanner_name AS name,
			COUNT(DISTINCT sbom_id) AS count
		FROM sbom_metadata_view
		WHERE scanner_name <> ''
		GROUP BY scanner_name
		ORDER BY count DESC, scanner_name ASC
	`).Scan(&resp.Scanners).Error; err != nil {
		return resp, err
	}

	// Recent SBOMs – join pre-aggregated library counts to avoid a correlated subquery per row.
	if err := db.WithContext(ctx).Raw(`
		SELECT
			m.sbom_id,
			m.created_at,
			m.scanner_name,
			m.scanner_version,
			m.asset_type,
			COALESCE(m.repo_id::text, '') AS repo_id,
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
			WHERE is_root = false
			GROUP BY sbom_id
		) lib ON lib.sbom_id = m.sbom_id
		ORDER BY m.created_at DESC
		LIMIT 8
	`).Scan(&resp.RecentSBOMs).Error; err != nil {
		return resp, err
	}

	// Top components by SBOM count
	if err := db.WithContext(ctx).Raw(`
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
		return resp, err
	}

	// Top licenses – scoped to current SBOMs only
	if err := db.WithContext(ctx).Raw(`
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
		return resp, err
	}

	return resp, nil
}
