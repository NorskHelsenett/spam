package db

import (
	"context"
	"fmt"
	"time"

	"gorm.io/gorm"
)

// hostExposureViewRefreshLockID guards refreshes of the host_exposure
// + exposed_digests pair. Distinct from the SBOM, unified-vuln, and
// asset_risk locks so a slow refresh on one family does not block
// another. Picked from the same private numeric range as the existing
// lock IDs (8_742_635_91x) so they're easy to diff in pg_locks.
const hostExposureViewRefreshLockID = 8_742_635_915

// hostExposureViewName / exposedDigestsViewName are the materialized
// views populated by 20260509_create_host_exposure_views.sql. They
// must refresh in the listed order: exposed_digests reads from
// host_exposure.
const (
	hostExposureViewName   = "host_exposure"
	exposedDigestsViewName = "exposed_digests"
)

// HostExposureViewsPopulated reports whether both host_exposure and
// exposed_digests are populated. The hosts list handler short-circuits
// to an empty response while either is still WITH NO DATA, mirroring
// how vulnmetrics / assetrisk handle their first-populate window.
func HostExposureViewsPopulated(ctx context.Context, db *gorm.DB) (bool, error) {
	var populated bool
	err := db.WithContext(ctx).Raw(
		"SELECT COALESCE(bool_and(ispopulated), false) FROM pg_matviews WHERE matviewname IN (?, ?)",
		hostExposureViewName, exposedDigestsViewName,
	).Scan(&populated).Error
	return populated, err
}

// RefreshHostExposureViews refreshes host_exposure and exposed_digests
// in dependency order under a dedicated session-level advisory lock so
// concurrent triggers across replicas serialise. Reuses refreshView for
// the CONCURRENTLY+fallback logic that handles "view not yet populated"
// gracefully. Returns ErrRefreshLockHeld when another process holds the
// lock.
func RefreshHostExposureViews(ctx context.Context, db *gorm.DB) error {
	names := []string{hostExposureViewName, exposedDigestsViewName}
	if materializedViewsRecentlyRefreshed(ctx, db, names, hostExposureViewRefreshInterval) {
		return nil
	}

	sqlDB, err := db.WithContext(ctx).DB()
	if err != nil {
		return fmt.Errorf("get raw db: %w", err)
	}
	conn, err := sqlDB.Conn(ctx)
	if err != nil {
		return fmt.Errorf("acquire db connection: %w", err)
	}
	defer conn.Close()

	var acquired bool
	if err := conn.QueryRowContext(ctx, "SELECT pg_try_advisory_lock($1)", hostExposureViewRefreshLockID).Scan(&acquired); err != nil {
		return fmt.Errorf("acquire host_exposure refresh lock: %w", err)
	}
	if !acquired {
		return ErrRefreshLockHeld
	}
	// See note on RefreshAssetRiskView — release on a fresh ctx so a
	// SIGTERM-cancelled parent ctx mid-refresh doesn't leak the
	// session-level advisory lock back into the connection pool.
	defer func() {
		releaseCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, _ = conn.ExecContext(releaseCtx, "SELECT pg_advisory_unlock($1)", hostExposureViewRefreshLockID)
	}()

	if materializedViewsRecentlyRefreshed(ctx, db, names, hostExposureViewRefreshInterval) {
		return nil
	}

	for _, view := range names {
		if err := refreshView(ctx, db, view); err != nil {
			return fmt.Errorf("refresh %s: %w", view, err)
		}
	}

	return recordMaterializedViewRefresh(ctx, db, names, time.Now().UTC())
}
