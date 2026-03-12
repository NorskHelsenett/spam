package vulnmetrics

import (
	"context"
	"time"

	"github.com/NorskHelsenett/spam/internal/cache"
	"gorm.io/gorm"
)

const (
	summaryCacheKey = "vuln:summary:v1"
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

type summaryVersion struct {
	LastTrivyAt *time.Time `json:"last_trivy_at" gorm:"column:last_trivy_at"`
	LastOSVAt   *time.Time `json:"last_osv_at" gorm:"column:last_osv_at"`
	LastVEXAt   *time.Time `json:"last_vex_at" gorm:"column:last_vex_at"`
}

type cachedSummary struct {
	Version summaryVersion `json:"version"`
	Summary Summary        `json:"summary"`
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

	if err := upsertSnapshot(ctx, db, capturedAt.UTC(), summary); err != nil {
		return Summary{}, err
	}

	return summary, nil
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
