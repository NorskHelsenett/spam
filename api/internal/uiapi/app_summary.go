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
const appSummaryCacheKey = "app:summary:v3"

// appSummaryMinRefreshGap caps how often the expensive aggregate is
// recomputed in the background. Without it, the watermark-driven stale
// check fires a recompute on every materialized-view refresh — and
// with the cross-replica coalescing those happen every ~30s under
// activity. The aggregate takes ~10s, so unbounded watermark-driven
// recomputes burn a sizable fraction of one core continuously even
// though users only ever see cached data. A 2-minute floor brings
// the duty cycle down without making dashboard counts visibly stale.
const appSummaryMinRefreshGap = 2 * time.Minute

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
	Name    string `json:"name"`
	Version string `json:"version"`
	Count   int64  `json:"count"`
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
	ImageID        string    `json:"image_id,omitempty"`
	ImageRegistry  string    `json:"image_registry,omitempty"`
	ImageRepo      string    `gorm:"column:image_repository" json:"image_repository,omitempty"`
	ImageDigest    string    `json:"image_digest,omitempty"`
	ComponentCount int64     `json:"component_count"`
	VulnCount      int64     `json:"vuln_count"`
	SecretCount    int64     `json:"secret_count"`
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
// ComputedAt is the wall-clock time the response was generated and is used to
// rate-limit the background refresh; ViewRefreshedAt is the MV watermark at
// compute time and is used to detect cache staleness.
type appSummaryCacheEntry struct {
	ViewRefreshedAt time.Time          `json:"view_refreshed_at"`
	ComputedAt      time.Time          `json:"computed_at"`
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
		// Cross-repo aggregate — admin or wildcard grant only in
		// Phase 3. Narrow grants fall through to 404 until a
		// per-subject scoped recomputation lands.
		if !requireUnrestrictedRepos(w, r) {
			return
		}

		watermark := appSummaryWatermark(r.Context(), db)

		if entry, ok, _ := cache.GetJSON[appSummaryCacheEntry](r.Context(), c, appSummaryCacheKey); ok {
			if !watermark.IsZero() && !entry.ViewRefreshedAt.Before(watermark) {
				// Cache is current with the materialized view.
				writeJSON(w, http.StatusOK, entry.Response)
				return
			}
			// Stale: serve immediately. Background refresh is rate-limited
			// to appSummaryMinRefreshGap so a chatty watermark (coalesced
			// MV refreshes every ~30s under activity) does not pin the
			// expensive aggregate to a recompute-per-watermark-tick cadence.
			writeJSON(w, http.StatusOK, entry.Response)
			if !entry.ComputedAt.IsZero() && time.Since(entry.ComputedAt) < appSummaryMinRefreshGap {
				return
			}
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
		ComputedAt:      time.Now().UTC(),
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

	// Scanners — include the most recent version per scanner
	if err := db.WithContext(ctx).Raw(`
		SELECT
			scanner_name AS name,
			(SELECT m2.scanner_version FROM sbom_metadata_view m2
			 WHERE m2.scanner_name = m.scanner_name AND m2.scanner_version <> ''
			 ORDER BY m2.created_at DESC LIMIT 1) AS version,
			COUNT(DISTINCT sbom_id) AS count
		FROM sbom_metadata_view m
		WHERE scanner_name <> ''
		GROUP BY scanner_name
		ORDER BY count DESC, scanner_name ASC
	`).Scan(&resp.Scanners).Error; err != nil {
		return resp, err
	}

	// Recent SBOMs – resolve identity fields from live tables so the row
	// doesn't go blank when sbom_metadata_view is stale. The materialized
	// view is still used for scanner name/version (those require parsing
	// the SBOM JSON and don't change after ingest).
	if err := db.WithContext(ctx).Raw(`
		WITH recent AS (
			SELECT sb.sbom_id, sb.asset_type, sb.asset_ref_id, s.created_at
			FROM sbom_bindings sb
			JOIN sboms s ON s.id = sb.sbom_id
			ORDER BY s.created_at DESC
			LIMIT 8
		),
		scan_latest AS (
			SELECT DISTINCT ON (repo_id)
				repo_id,
				critical_count + high_count + medium_count + low_count + unknown_count AS total
			FROM sbom_scan_results
			ORDER BY repo_id, scanned_at DESC
		),
		image_vulns AS (
			SELECT image_digest_id AS image_id, COUNT(*) AS total
			FROM image_vuln_findings
			GROUP BY image_digest_id
		),
		repo_secret_latest AS (
			SELECT DISTINCT ON (repo_id)
				repo_id,
				jsonb_array_length(COALESCE(findings, '[]'::jsonb)) AS total
			FROM run_secrets
			WHERE repo_id IS NOT NULL AND repo_id <> ''
			ORDER BY repo_id, created_at DESC
		)
		SELECT
			r.sbom_id,
			r.created_at,
			COALESCE(mv.scanner_name, '') AS scanner_name,
			COALESCE(mv.scanner_version, '') AS scanner_version,
			r.asset_type,
			COALESCE(rc.repo_id::text, '') AS repo_id,
			COALESCE(rp.org || '/' || rp.slug, '') AS repo_name,
			COALESCE(rc.commit_sha, '') AS commit_sha,
			-- Prefer direct image_digests lookup, but fall back to the
			-- materialized view when the direct join misses (e.g. the
			-- reconciler hasn't harvested this digest yet, or there's a
			-- type cast quirk on asset_ref_id). Without the fallback the
			-- Latest activity row goes blank and the UI collapses to the
			-- first 8 chars of the sbom_id.
			COALESCE(NULLIF(imd.id::text, ''), NULLIF(mv.image_id::text, ''), '') AS image_id,
			COALESCE(NULLIF(imd.registry, ''), mv.image_registry, '') AS image_registry,
			COALESCE(NULLIF(imd.repository, ''), mv.image_repository, '') AS image_repository,
			COALESCE(imd.digest, '') AS image_digest,
			COALESCE(lib.component_count, 0) AS component_count,
			COALESCE(tv.total, iv.total, 0) AS vuln_count,
			COALESCE(rs.total, 0) AS secret_count
		FROM recent r
		LEFT JOIN sbom_metadata_view mv
			ON mv.sbom_id = r.sbom_id
			AND mv.asset_type = r.asset_type
			AND mv.asset_ref_id = r.asset_ref_id
		LEFT JOIN repo_commits rc
			ON rc.id = r.asset_ref_id AND r.asset_type = 'REPO_COMMIT'
		LEFT JOIN repos rp ON rp.id = rc.repo_id
		LEFT JOIN image_digests imd
			ON imd.id = r.asset_ref_id AND r.asset_type = 'IMAGE_DIGEST'
		LEFT JOIN (
			SELECT sbom_id, COUNT(*) AS component_count
			FROM sbom_component_view
			WHERE is_root = false
			GROUP BY sbom_id
		) lib ON lib.sbom_id = r.sbom_id
		LEFT JOIN scan_latest tv ON tv.repo_id::text = rc.repo_id::text
		LEFT JOIN image_vulns iv ON iv.image_id::text = imd.id::text
		LEFT JOIN repo_secret_latest rs ON rs.repo_id::text = rc.repo_id::text
		ORDER BY r.created_at DESC
	`).Scan(&resp.RecentSBOMs).Error; err != nil {
		return resp, err
	}

	// Backfill component_count for rows where sbom_component_view hasn't
	// caught up (view is refreshed periodically, so freshly-bound SBOMs show
	// 0 until then). Parse the raw SBOM content for those — capped to the 8
	// rows already in RecentSBOMs.
	for i := range resp.RecentSBOMs {
		if resp.RecentSBOMs[i].ComponentCount > 0 {
			continue
		}
		var sbom struct {
			Format       string
			ContentBytes []byte
		}
		if err := db.WithContext(ctx).Table("sboms").
			Select("format, content_bytes").
			Where("id = ?", resp.RecentSBOMs[i].SBOMID).
			First(&sbom).Error; err != nil {
			continue
		}
		resp.RecentSBOMs[i].ComponentCount = sbomComponentCount(ctx, db, resp.RecentSBOMs[i].SBOMID, sbom.Format, sbom.ContentBytes)
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
