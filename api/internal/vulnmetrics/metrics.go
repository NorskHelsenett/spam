package vulnmetrics

import (
	"context"
	"time"

	"github.com/NorskHelsenett/spam/internal/cache"
	"gorm.io/gorm"
)

const (
	summaryCacheKey = "vuln:summary:v1"
	reposCacheKey   = "vuln:repos:v1"
	listCacheKey    = "vuln:list:v1"
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

type VulnRow struct {
	RepoID           string `json:"repo_id" gorm:"column:repo_id"`
	RepoSlug         string `json:"repo_slug" gorm:"column:repo_slug"`
	VulnID           string `json:"vuln_id" gorm:"column:vuln_id"`
	Severity         string `json:"severity" gorm:"column:severity"`
	PkgName          string `json:"pkg_name" gorm:"column:pkg_name"`
	InstalledVersion string `json:"installed_version" gorm:"column:installed_version"`
	FixedVersion     string `json:"fixed_version" gorm:"column:fixed_version"`
	Title            string `json:"title" gorm:"column:title"`
	Description      string `json:"description" gorm:"column:description"`
	Source           string `json:"source" gorm:"column:source"`
}

type summaryVersion struct {
	LastTrivyAt *time.Time `json:"last_trivy_at" gorm:"column:last_trivy_at"`
	LastOSVAt   *time.Time `json:"last_osv_at" gorm:"column:last_osv_at"`
	LastVEXAt   *time.Time `json:"last_vex_at" gorm:"column:last_vex_at"`
}

type cachedSummary struct {
	Version summaryVersion `json:"version"`
	Summary Summary        `json:"summary"`
}

type cachedRepos struct {
	Version summaryVersion `json:"version"`
	Rows    []RepoRow      `json:"rows"`
}

type cachedList struct {
	Version summaryVersion `json:"version"`
	Rows    []VulnRow      `json:"rows"`
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
	list, err := computeList(ctx, db)
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
	if err := cache.SetJSON(ctx, store, listCacheKey, cachedList{
		Version: version,
		Rows:    list,
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
	for _, key := range []string{summaryCacheKey, reposCacheKey, listCacheKey} {
		if err := store.Delete(ctx, key); err != nil {
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

func LoadList(ctx context.Context, db *gorm.DB) ([]VulnRow, error) {
	store := cache.NewPostgresStore(db)
	version, err := querySummaryVersion(ctx, db)
	if err != nil {
		return nil, err
	}
	if entry, ok, err := cache.GetJSON[cachedList](ctx, store, listCacheKey); err == nil && ok {
		if sameVersion(entry.Version, version) {
			return entry.Rows, nil
		}
	}

	rows, err := computeList(ctx, db)
	if err != nil {
		return nil, err
	}
	if err := cache.SetJSON(ctx, store, listCacheKey, cachedList{
		Version: version,
		Rows:    rows,
	}, summaryCacheTTL); err != nil {
		return nil, err
	}
	return rows, nil
}

func computeSummary(ctx context.Context, db *gorm.DB) (Summary, error) {
	var summary Summary

	if err := db.WithContext(ctx).Raw(`
		SELECT
			COUNT(*) FILTER (WHERE severity = 'CRITICAL')::int AS total_critical,
			COUNT(*) FILTER (WHERE severity = 'HIGH')::int     AS total_high,
			COUNT(*) FILTER (WHERE severity = 'MEDIUM')::int   AS total_medium,
			COUNT(*) FILTER (WHERE severity = 'LOW')::int      AS total_low,
			COUNT(*) FILTER (WHERE severity NOT IN ('CRITICAL','HIGH','MEDIUM','LOW'))::int AS total_unknown
		FROM view_unified_repositories_vulnerabilities
	`).Scan(&summary).Error; err != nil {
		return Summary{}, err
	}

	type trivyMeta struct {
		ScannedSBOMs  int        `gorm:"column:scanned_sboms"`
		LastScannedAt *time.Time `gorm:"column:last_scanned_at"`
	}
	var meta trivyMeta
	if err := db.WithContext(ctx).Raw(`
		SELECT
			COUNT(DISTINCT sbom_id)::int AS scanned_sboms,
			MAX(scanned_at)              AS last_scanned_at
		FROM trivy_scan_results
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
			(SELECT MAX(scanned_at) FROM trivy_scan_results)        AS last_trivy_at,
			(SELECT MAX(checked_at) FROM component_vulnerabilities) AS last_osv_at,
			(SELECT MAX(created_at) FROM component_vex)             AS last_vex_at
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

func computeList(ctx context.Context, db *gorm.DB) ([]VulnRow, error) {
	var rows []VulnRow
	if err := db.WithContext(ctx).Raw(`
		SELECT repo_id, repo_slug, vuln_id, severity, pkg_name, installed_version, fixed_version, title, description, source
		FROM view_unified_repositories_vulnerabilities
		ORDER BY
			CASE severity
				WHEN 'CRITICAL' THEN 1
				WHEN 'HIGH'     THEN 2
				WHEN 'MEDIUM'   THEN 3
				WHEN 'LOW'      THEN 4
				ELSE 5
			END,
			vuln_id
		LIMIT 5000
	`).Scan(&rows).Error; err != nil {
		return nil, err
	}
	if rows == nil {
		rows = []VulnRow{}
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
	return sameTime(a.LastTrivyAt, b.LastTrivyAt) &&
		sameTime(a.LastOSVAt, b.LastOSVAt) &&
		sameTime(a.LastVEXAt, b.LastVEXAt)
}

func sameTime(a, b *time.Time) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return a.Equal(*b)
}
