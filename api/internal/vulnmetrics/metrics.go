package vulnmetrics

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/NorskHelsenett/spam/internal/cache"
	"gorm.io/gorm"
)

const (
	summaryCacheKey = "vuln:summary:v1"
	reposCacheKey   = "vuln:repos:v1"
	summaryCacheTTL = 7 * 24 * time.Hour
)

type Summary struct {
	TotalCritical int        `json:"total_critical" gorm:"column:total_critical"`
	TotalHigh     int        `json:"total_high" gorm:"column:total_high"`
	TotalMedium   int        `json:"total_medium" gorm:"column:total_medium"`
	TotalLow      int        `json:"total_low" gorm:"column:total_low"`
	TotalUnknown  int        `json:"total_unknown" gorm:"column:total_unknown"`
	TotalVulns    int        `json:"total_vulns"`
	ScannedSBOMs  int        `json:"scanned_sboms" gorm:"column:scanned_sboms"`
	LastScannedAt *time.Time `json:"last_scanned_at" gorm:"column:last_scanned_at"`
}

type TrendPoint struct {
	Date     string `json:"date" gorm:"column:date"`
	Critical int    `json:"critical" gorm:"column:critical"`
	High     int    `json:"high" gorm:"column:high"`
	Medium   int    `json:"medium" gorm:"column:medium"`
	Low      int    `json:"low" gorm:"column:low"`
	Unknown  int    `json:"unknown" gorm:"column:unknown"`
}

type RepoRow struct {
	RepoID        string     `json:"repo_id" gorm:"column:repo_id"`
	RepoSlug      string     `json:"repo_slug" gorm:"column:repo_slug"`
	CriticalCount int        `json:"critical_count" gorm:"column:critical_count"`
	HighCount     int        `json:"high_count" gorm:"column:high_count"`
	MediumCount   int        `json:"medium_count" gorm:"column:medium_count"`
	LowCount      int        `json:"low_count" gorm:"column:low_count"`
	UnknownCount  int        `json:"unknown_count" gorm:"column:unknown_count"`
	LastScannedAt *time.Time `json:"last_scanned_at" gorm:"column:last_scanned_at"`
}

// VulnAsset is one surface a vulnerability appears on — either a source
// repo (type = "repo") or a container image (type = "image"). ID is the
// underlying DB id (repos.id or image_digests.id); Slug is a human-
// readable label for tooltips.
type VulnAsset struct {
	Type string `json:"type"`
	ID   string `json:"id"`
	Slug string `json:"slug"`
}

// VulnGroup is one row in the /api/vuln/list response: a single CVE /
// advisory rolled up across every asset it was found on. Fields like
// pkg_name / installed_version come from the worst-severity row
// contributing to the group, which is almost always stable across
// sources for the same advisory.
type VulnGroup struct {
	VulnID           string      `json:"vuln_id"`
	Severity         string      `json:"severity"`
	PkgName          string      `json:"pkg_name"`
	InstalledVersion string      `json:"installed_version"`
	FixedVersion     string      `json:"fixed_version"`
	Title            string      `json:"title"`
	Description      string      `json:"description"`
	Sources          []string    `json:"sources"`
	Assets           []VulnAsset `json:"assets"`
	RepoCount        int         `json:"repo_count"`
	ImageCount       int         `json:"image_count"`
}

// VulnListResponse is the paginated shape of /api/vuln/list. Total
// counts distinct vuln_ids matching the filters (NOT the raw asset
// rows), so the client can size a virtual scroller by group count.
type VulnListResponse struct {
	Total  int         `json:"total"`
	Limit  int         `json:"limit"`
	Offset int         `json:"offset"`
	Items  []VulnGroup `json:"items"`
}

// VulnListParams captures every query-string filter plus the
// pre-computed ACL fragments the handler is responsible for building.
type VulnListParams struct {
	Limit      int
	Offset     int
	Severities []string
	Query      string
	Sources    []string
	FixOnly    bool
	Years      []string
	RepoID     string

	// RepoSQL filters rows from the repo-side UNION branch. Fragment is
	// interpolated verbatim as a WHERE predicate on the repos-view row;
	// use "TRUE" for unrestricted, "FALSE" to exclude all repo rows.
	RepoSQL  string
	RepoArgs []any

	// ImageSQL filters rows from the image-side UNION branch against
	// image_digests. Same semantics as RepoSQL.
	ImageSQL  string
	ImageArgs []any
}

type summaryVersion struct {
	LastScanAt      *time.Time `json:"last_scan_at" gorm:"column:last_scan_at"`
	LastOSVAt       *time.Time `json:"last_osv_at" gorm:"column:last_osv_at"`
	LastVEXAt       *time.Time `json:"last_vex_at" gorm:"column:last_vex_at"`
	LastImageScanAt *time.Time `json:"last_image_scan_at" gorm:"column:last_image_scan_at"`
}

type cachedSummary struct {
	Version summaryVersion `json:"version"`
	Summary Summary        `json:"summary"`
}

type cachedRepos struct {
	Version summaryVersion `json:"version"`
	Rows    []RepoRow      `json:"rows"`
}

func LoadSummary(ctx context.Context, db *gorm.DB) (Summary, error) {
	store := cache.NewPostgresStore(db)

	version, err := querySummaryVersion(ctx, db)
	if err != nil {
		return Summary{}, err
	}

	if entry, ok, err := cache.GetJSON[cachedSummary](ctx, store, summaryCacheKey); err == nil && ok {
		if sameVersion(entry.Version, version) {
			return entry.Summary, nil
		}
	}

	return Refresh(ctx, db, time.Now().UTC())
}

func Refresh(ctx context.Context, db *gorm.DB, capturedAt time.Time) (Summary, error) {
	summary, err := computeSummary(ctx, db)
	if err != nil {
		return Summary{}, err
	}
	repos, err := computeRepos(ctx, db)
	if err != nil {
		return Summary{}, err
	}
	version, err := querySummaryVersion(ctx, db)
	if err != nil {
		return Summary{}, err
	}

	store := cache.NewPostgresStore(db)
	if err := cache.SetJSON(ctx, store, summaryCacheKey, cachedSummary{
		Version: version,
		Summary: summary,
	}, summaryCacheTTL); err != nil {
		return Summary{}, err
	}
	if err := cache.SetJSON(ctx, store, reposCacheKey, cachedRepos{
		Version: version,
		Rows:    repos,
	}, summaryCacheTTL); err != nil {
		return Summary{}, err
	}

	if err := upsertSnapshot(ctx, db, capturedAt.UTC(), summary); err != nil {
		return Summary{}, err
	}

	return summary, nil
}

func Clear(ctx context.Context, db *gorm.DB) error {
	store := cache.NewPostgresStore(db)
	for _, key := range []string{summaryCacheKey, reposCacheKey} {
		if err := cache.Delete(ctx, store, key); err != nil {
			return err
		}
	}
	return nil
}

func LoadTrend(ctx context.Context, db *gorm.DB, days int) ([]TrendPoint, error) {
	var rows []TrendPoint
	if err := db.WithContext(ctx).Raw(`
		SELECT
			TO_CHAR(snapshot_date, 'YYYY-MM-DD') AS date,
			critical,
			high,
			medium,
			low,
			unknown
		FROM vuln_dashboard_snapshots
		WHERE snapshot_date >= CURRENT_DATE - (? - 1)
		ORDER BY snapshot_date ASC
	`, days).Scan(&rows).Error; err != nil {
		return nil, err
	}
	if rows == nil {
		rows = []TrendPoint{}
	}
	return rows, nil
}

func LoadRepos(ctx context.Context, db *gorm.DB) ([]RepoRow, error) {
	store := cache.NewPostgresStore(db)
	version, err := querySummaryVersion(ctx, db)
	if err != nil {
		return nil, err
	}
	if entry, ok, err := cache.GetJSON[cachedRepos](ctx, store, reposCacheKey); err == nil && ok {
		if sameVersion(entry.Version, version) {
			return entry.Rows, nil
		}
	}

	rows, err := computeRepos(ctx, db)
	if err != nil {
		return nil, err
	}
	if err := cache.SetJSON(ctx, store, reposCacheKey, cachedRepos{
		Version: version,
		Rows:    rows,
	}, summaryCacheTTL); err != nil {
		return nil, err
	}
	return rows, nil
}

// LoadListPage returns a paginated page of grouped vulnerabilities,
// plus the total group count for the same filters. Results are
// per-caller (ACL-dependent) so the output is not cached.
func LoadListPage(ctx context.Context, db *gorm.DB, p VulnListParams) (VulnListResponse, error) {
	if p.Limit <= 0 {
		p.Limit = 100
	}
	if p.Limit > 500 {
		p.Limit = 500
	}
	if p.Offset < 0 {
		p.Offset = 0
	}

	base, args := buildAssetUnionSQL(p)

	// Row-level filters on the UNION result (apply before GROUP BY so
	// they reduce the set the aggregate sees).
	var where []string
	var whereArgs []any
	if len(p.Severities) > 0 {
		where = append(where, "severity IN ?")
		whereArgs = append(whereArgs, p.Severities)
	}
	if len(p.Sources) > 0 {
		where = append(where, "source IN ?")
		whereArgs = append(whereArgs, p.Sources)
	}
	if p.FixOnly {
		where = append(where, "fixed_version <> ''")
	}
	if q := strings.TrimSpace(p.Query); q != "" {
		needle := "%" + strings.ToLower(q) + "%"
		where = append(where,
			"(LOWER(vuln_id) LIKE ? OR LOWER(title) LIKE ? OR LOWER(pkg_name) LIKE ? OR LOWER(asset_slug) LIKE ?)")
		whereArgs = append(whereArgs, needle, needle, needle, needle)
	}
	if len(p.Years) > 0 {
		// vuln_id pattern is "<prefix>-YYYY-NNNN" (CVE-2024-1234,
		// GHSA rarely fits but we don't support it here). Match the
		// literal "-YYYY-" substring.
		var parts []string
		for _, y := range p.Years {
			parts = append(parts, "vuln_id ILIKE ?")
			whereArgs = append(whereArgs, "%-"+y+"-%")
		}
		where = append(where, "("+strings.Join(parts, " OR ")+")")
	}

	var whereClause string
	if len(where) > 0 {
		whereClause = "WHERE " + strings.Join(where, " AND ")
	}

	// Total count = distinct vuln_id after filters.
	var total int
	countSQL := fmt.Sprintf(`
		WITH asset_vulns AS (%s)
		SELECT COUNT(DISTINCT vuln_id)::int FROM asset_vulns %s
	`, base, whereClause)
	countArgs := append([]any{}, args...)
	countArgs = append(countArgs, whereArgs...)
	if err := db.WithContext(ctx).Raw(countSQL, countArgs...).Scan(&total).Error; err != nil {
		return VulnListResponse{}, err
	}

	// Grouped page.
	groupSQL := fmt.Sprintf(`
		WITH asset_vulns AS (%s),
		ranked AS (
			SELECT *,
				CASE severity
					WHEN 'CRITICAL' THEN 1
					WHEN 'HIGH'     THEN 2
					WHEN 'MEDIUM'   THEN 3
					WHEN 'LOW'      THEN 4
					ELSE 5
				END AS sev_rank
			FROM asset_vulns
			%s
		)
		SELECT
			vuln_id,
			MIN(sev_rank) AS sev_rank,
			(ARRAY_AGG(severity ORDER BY sev_rank ASC, asset_id ASC))[1]           AS severity,
			(ARRAY_AGG(pkg_name ORDER BY sev_rank ASC, asset_id ASC))[1]           AS pkg_name,
			(ARRAY_AGG(installed_version ORDER BY sev_rank ASC, asset_id ASC))[1]  AS installed_version,
			(ARRAY_AGG(fixed_version ORDER BY sev_rank ASC, asset_id ASC))[1]      AS fixed_version,
			(ARRAY_AGG(title ORDER BY sev_rank ASC, asset_id ASC))[1]              AS title,
			(ARRAY_AGG(description ORDER BY sev_rank ASC, asset_id ASC))[1]        AS description,
			COALESCE(
				(SELECT jsonb_agg(DISTINCT s) FROM unnest(ARRAY_AGG(source)) AS s WHERE s IS NOT NULL AND s <> ''),
				'[]'::jsonb
			) AS sources,
			jsonb_agg(DISTINCT jsonb_build_object(
				'type', asset_type, 'id', asset_id, 'slug', asset_slug
			)) AS assets,
			COUNT(DISTINCT CASE WHEN asset_type = 'repo'  THEN asset_id END)::int AS repo_count,
			COUNT(DISTINCT CASE WHEN asset_type = 'image' THEN asset_id END)::int AS image_count
		FROM ranked
		GROUP BY vuln_id
		ORDER BY sev_rank ASC, vuln_id ASC
		LIMIT ? OFFSET ?
	`, base, whereClause)

	groupArgs := append([]any{}, args...)
	groupArgs = append(groupArgs, whereArgs...)
	groupArgs = append(groupArgs, p.Limit, p.Offset)

	type groupRow struct {
		VulnID           string          `gorm:"column:vuln_id"`
		SevRank          int             `gorm:"column:sev_rank"`
		Severity         string          `gorm:"column:severity"`
		PkgName          string          `gorm:"column:pkg_name"`
		InstalledVersion string          `gorm:"column:installed_version"`
		FixedVersion     string          `gorm:"column:fixed_version"`
		Title            string          `gorm:"column:title"`
		Description      string          `gorm:"column:description"`
		Sources          json.RawMessage `gorm:"column:sources"`
		Assets           json.RawMessage `gorm:"column:assets"`
		RepoCount        int             `gorm:"column:repo_count"`
		ImageCount       int             `gorm:"column:image_count"`
	}
	var raws []groupRow
	if err := db.WithContext(ctx).Raw(groupSQL, groupArgs...).Scan(&raws).Error; err != nil {
		return VulnListResponse{}, err
	}

	items := make([]VulnGroup, 0, len(raws))
	for _, r := range raws {
		var sources []string
		if len(r.Sources) > 0 {
			_ = json.Unmarshal(r.Sources, &sources)
		}
		var assets []VulnAsset
		if len(r.Assets) > 0 {
			_ = json.Unmarshal(r.Assets, &assets)
		}
		if sources == nil {
			sources = []string{}
		}
		if assets == nil {
			assets = []VulnAsset{}
		}
		items = append(items, VulnGroup{
			VulnID:           r.VulnID,
			Severity:         r.Severity,
			PkgName:          r.PkgName,
			InstalledVersion: r.InstalledVersion,
			FixedVersion:     r.FixedVersion,
			Title:            r.Title,
			Description:      r.Description,
			Sources:          sources,
			Assets:           assets,
			RepoCount:        r.RepoCount,
			ImageCount:       r.ImageCount,
		})
	}

	return VulnListResponse{
		Total:  total,
		Limit:  p.Limit,
		Offset: p.Offset,
		Items:  items,
	}, nil
}

// buildAssetUnionSQL returns the CTE body plus its bind args. Repo and
// image branches each carry their own ACL fragment (defaults to "TRUE"
// so the caller cannot accidentally broaden scope by omitting one).
func buildAssetUnionSQL(p VulnListParams) (string, []any) {
	repoSQL := strings.TrimSpace(p.RepoSQL)
	if repoSQL == "" {
		repoSQL = "TRUE"
	}
	imageSQL := strings.TrimSpace(p.ImageSQL)
	if imageSQL == "" {
		imageSQL = "TRUE"
	}

	// Fast-path: narrowing to a single repo excludes the image branch
	// entirely so image vulns don't leak into a repo-detail drill-down.
	if p.RepoID != "" {
		repoSQL = fmt.Sprintf("(%s) AND v.repo_id = ?", repoSQL)
		imageSQL = "FALSE"
	}

	base := fmt.Sprintf(`
		SELECT
			'repo'::text                                AS asset_type,
			v.repo_id                                   AS asset_id,
			v.repo_slug                                 AS asset_slug,
			v.vuln_id, v.severity, v.pkg_name,
			v.installed_version, v.fixed_version,
			v.title, v.description, v.source
		FROM view_unified_repositories_vulnerabilities v
		WHERE %s
		UNION ALL
		SELECT
			'image'::text                               AS asset_type,
			v.image_id                                  AS asset_id,
			v.image_slug                                AS asset_slug,
			v.vuln_id, v.severity, v.pkg_name,
			v.installed_version, v.fixed_version,
			v.title, v.description, v.source
		FROM view_unified_image_vulnerabilities v
		WHERE %s
	`, repoSQL, imageSQL)

	var args []any
	args = append(args, p.RepoArgs...)
	if p.RepoID != "" {
		args = append(args, p.RepoID)
	}
	args = append(args, p.ImageArgs...)
	return base, args
}

func computeSummary(ctx context.Context, db *gorm.DB) (Summary, error) {
	var summary Summary

	// Count across both repo-side and image-side vulns.
	if err := db.WithContext(ctx).Raw(`
		WITH u AS (
			SELECT severity FROM view_unified_repositories_vulnerabilities
			UNION ALL
			SELECT severity FROM view_unified_image_vulnerabilities
		)
		SELECT
			COUNT(*) FILTER (WHERE severity = 'CRITICAL')::int AS total_critical,
			COUNT(*) FILTER (WHERE severity = 'HIGH')::int     AS total_high,
			COUNT(*) FILTER (WHERE severity = 'MEDIUM')::int   AS total_medium,
			COUNT(*) FILTER (WHERE severity = 'LOW')::int      AS total_low,
			COUNT(*) FILTER (WHERE severity NOT IN ('CRITICAL','HIGH','MEDIUM','LOW'))::int AS total_unknown
		FROM u
	`).Scan(&summary).Error; err != nil {
		return Summary{}, err
	}

	type scanMeta struct {
		ScannedSBOMs  int        `gorm:"column:scanned_sboms"`
		LastScannedAt *time.Time `gorm:"column:last_scanned_at"`
	}
	var meta scanMeta
	if err := db.WithContext(ctx).Raw(`
		WITH sboms_all AS (
			SELECT sbom_id FROM sbom_scan_results
			UNION
			SELECT sb.sbom_id
			FROM sbom_bindings sb
			JOIN image_scan_runs isr ON isr.image_digest_id = sb.asset_ref_id
			WHERE sb.asset_type = 'IMAGE_DIGEST'
			  AND isr.finished_at IS NOT NULL
		),
		ts AS (
			SELECT MAX(scanned_at) AS t FROM sbom_scan_results
			UNION ALL
			SELECT MAX(finished_at) FROM image_scan_runs
		)
		SELECT
			(SELECT COUNT(*) FROM sboms_all)::int AS scanned_sboms,
			(SELECT MAX(t) FROM ts)               AS last_scanned_at
	`).Scan(&meta).Error; err != nil {
		return Summary{}, err
	}

	summary.ScannedSBOMs = meta.ScannedSBOMs
	summary.LastScannedAt = meta.LastScannedAt
	summary.TotalVulns = summary.TotalCritical + summary.TotalHigh + summary.TotalMedium + summary.TotalLow + summary.TotalUnknown

	return summary, nil
}

func querySummaryVersion(ctx context.Context, db *gorm.DB) (summaryVersion, error) {
	var version summaryVersion
	err := db.WithContext(ctx).Raw(`
		SELECT
			(SELECT MAX(scanned_at) FROM sbom_scan_results)         AS last_scan_at,
			(SELECT MAX(checked_at) FROM component_vulnerabilities) AS last_osv_at,
			(SELECT MAX(created_at) FROM component_vex)             AS last_vex_at,
			(SELECT MAX(finished_at) FROM image_scan_runs)          AS last_image_scan_at
	`).Scan(&version).Error
	return version, err
}

func computeRepos(ctx context.Context, db *gorm.DB) ([]RepoRow, error) {
	var rows []RepoRow
	if err := db.WithContext(ctx).Raw(`
		SELECT
			repo_id,
			MAX(repo_slug) AS repo_slug,
			COUNT(*) FILTER (WHERE severity = 'CRITICAL')::int AS critical_count,
			COUNT(*) FILTER (WHERE severity = 'HIGH')::int     AS high_count,
			COUNT(*) FILTER (WHERE severity = 'MEDIUM')::int   AS medium_count,
			COUNT(*) FILTER (WHERE severity = 'LOW')::int      AS low_count,
			COUNT(*) FILTER (WHERE severity NOT IN ('CRITICAL','HIGH','MEDIUM','LOW'))::int AS unknown_count,
			MAX(scanned_at) AS last_scanned_at
		FROM view_unified_repositories_vulnerabilities
		GROUP BY repo_id
		ORDER BY critical_count DESC, high_count DESC, medium_count DESC
	`).Scan(&rows).Error; err != nil {
		return nil, err
	}
	if rows == nil {
		rows = []RepoRow{}
	}
	return rows, nil
}

func upsertSnapshot(ctx context.Context, db *gorm.DB, capturedAt time.Time, summary Summary) error {
	snapshotDate := time.Date(capturedAt.Year(), capturedAt.Month(), capturedAt.Day(), 0, 0, 0, 0, time.UTC)
	return db.WithContext(ctx).Exec(`
		INSERT INTO vuln_dashboard_snapshots (
			snapshot_date,
			critical,
			high,
			medium,
			low,
			unknown,
			total_vulns,
			scanned_sboms,
			last_scanned_at,
			captured_at
		)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (snapshot_date) DO UPDATE SET
			critical = EXCLUDED.critical,
			high = EXCLUDED.high,
			medium = EXCLUDED.medium,
			low = EXCLUDED.low,
			unknown = EXCLUDED.unknown,
			total_vulns = EXCLUDED.total_vulns,
			scanned_sboms = EXCLUDED.scanned_sboms,
			last_scanned_at = EXCLUDED.last_scanned_at,
			captured_at = EXCLUDED.captured_at
	`, snapshotDate, summary.TotalCritical, summary.TotalHigh, summary.TotalMedium, summary.TotalLow, summary.TotalUnknown, summary.TotalVulns, summary.ScannedSBOMs, summary.LastScannedAt, capturedAt).Error
}

func sameVersion(a, b summaryVersion) bool {
	return sameTime(a.LastScanAt, b.LastScanAt) &&
		sameTime(a.LastOSVAt, b.LastOSVAt) &&
		sameTime(a.LastVEXAt, b.LastVEXAt) &&
		sameTime(a.LastImageScanAt, b.LastImageScanAt)
}

func sameTime(a, b *time.Time) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return a.Equal(*b)
}
