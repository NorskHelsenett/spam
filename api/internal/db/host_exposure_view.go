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
//
// The bool reports whether the refresh may have changed view contents
// for downstream consumers — false means the debounce window or the
// cluster_record source fingerprint short-circuited, or the refresh
// ran only as a last_seen backstop with an unchanged fingerprint. The
// hostexposure trigger gate uses it to cascade asset_risk (and wake
// hostresolve) only when the views it consumes actually changed.
func RefreshHostExposureViews(ctx context.Context, db *gorm.DB) (bool, error) {
	names := []string{hostExposureViewName, exposedDigestsViewName}
	if materializedViewsRecentlyRefreshed(ctx, db, names, hostExposureViewRefreshInterval) {
		return false, nil
	}

	// Both MVs derive from cluster_record (plus the tiny clusters
	// name table) — skip the rebuild when nothing changed since the
	// last refresh, with a 30-minute backstop for the heartbeat-driven
	// last_seen column on host_exposure. exposed_digests is one of the
	// most expensive MVs in the schema, and most off-peak triggers are
	// no-op heartbeats.
	//
	// sourceUnchanged also feeds the return value: a backstop refresh
	// (fingerprint matched, refresh ran only to advance last_seen)
	// leaves exposed_digests — which has no heartbeat columns —
	// byte-identical, so reporting it as "changed" would pointlessly
	// cascade an asset_risk rebuild.
	sourceVersion := clusterRecordSourceVersion(ctx, db)
	sourceUnchanged := materializedViewsSourceVersionMatches(ctx, db, names, sourceVersion)
	if sourceUnchanged && materializedViewsRecentlyRefreshed(ctx, db, names, clusterDerivedViewMaxSkipAge) {
		return false, nil
	}

	sqlDB, err := db.WithContext(ctx).DB()
	if err != nil {
		return false, fmt.Errorf("get raw db: %w", err)
	}
	conn, err := sqlDB.Conn(ctx)
	if err != nil {
		return false, fmt.Errorf("acquire db connection: %w", err)
	}
	defer conn.Close()

	var acquired bool
	if err := conn.QueryRowContext(ctx, "SELECT pg_try_advisory_lock($1)", hostExposureViewRefreshLockID).Scan(&acquired); err != nil {
		return false, fmt.Errorf("acquire host_exposure refresh lock: %w", err)
	}
	if !acquired {
		return false, ErrRefreshLockHeld
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
		return false, nil
	}

	for _, view := range names {
		if err := refreshView(ctx, db, view); err != nil {
			return false, fmt.Errorf("refresh %s: %w", view, err)
		}
	}

	return !sourceUnchanged, recordMaterializedViewRefresh(ctx, db, names, time.Now().UTC(), sourceVersion)
}
