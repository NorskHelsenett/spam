package db

import (
	"context"
	"fmt"
	"time"

	"gorm.io/gorm"
)

// clusterSummaryViewRefreshLockID guards refreshes of the cluster_summary
// MV. Distinct from the SBOM, vuln, asset_risk, and host_exposure locks
// so a slow refresh on one family does not block another. Same private
// numeric range (8_742_635_91x) for easy diffing in pg_locks.
const clusterSummaryViewRefreshLockID = 8_742_635_916

const (
	clusterSummaryViewName  = "cluster_summary"
	clusterImageViewName    = "cluster_image_inventory"
)

// clusterMVNames are the MVs refreshed together by
// RefreshClusterSummaryView. Both project off cluster_record's running
// Container rows; sharing the refresh keeps their freshness aligned and
// halves the trigger overhead.
var clusterMVNames = []string{
	clusterSummaryViewName,
	clusterImageViewName,
}

// ClusterSummaryViewPopulated reports whether cluster_summary is
// populated. Used as the cold-start gate on ClusterSummaryHandler.
// Split from the image-side gate so adding a new MV to the family
// doesn't briefly black out the existing endpoints while the new one
// runs its first populate.
func ClusterSummaryViewPopulated(ctx context.Context, db *gorm.DB) (bool, error) {
	var populated bool
	err := db.WithContext(ctx).Raw(
		"SELECT COALESCE(ispopulated, false) FROM pg_matviews WHERE matviewname = ?",
		clusterSummaryViewName,
	).Scan(&populated).Error
	return populated, err
}

// ClusterImageInventoryPopulated reports whether cluster_image_inventory
// is populated. Gates the registry-distribution and images/detail
// handlers separately from cluster_summary.
func ClusterImageInventoryPopulated(ctx context.Context, db *gorm.DB) (bool, error) {
	var populated bool
	err := db.WithContext(ctx).Raw(
		"SELECT COALESCE(ispopulated, false) FROM pg_matviews WHERE matviewname = ?",
		clusterImageViewName,
	).Scan(&populated).Error
	return populated, err
}

// RefreshClusterSummaryView refreshes the cluster-side MVs
// (cluster_summary + cluster_image_inventory) under a dedicated
// session-level advisory lock so concurrent triggers across replicas
// serialise. Reuses refreshView for the CONCURRENTLY+fallback logic
// that handles "view not yet populated" gracefully. Returns
// ErrRefreshLockHeld when another process holds the lock.
func RefreshClusterSummaryView(ctx context.Context, db *gorm.DB) error {
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
	if err := conn.QueryRowContext(ctx, "SELECT pg_try_advisory_lock($1)", clusterSummaryViewRefreshLockID).Scan(&acquired); err != nil {
		return fmt.Errorf("acquire cluster_summary refresh lock: %w", err)
	}
	if !acquired {
		return ErrRefreshLockHeld
	}
	// Release on a fresh ctx so a SIGTERM-cancelled parent ctx mid-refresh
	// doesn't leak the session-level advisory lock back into the pool.
	defer func() {
		releaseCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, _ = conn.ExecContext(releaseCtx, "SELECT pg_advisory_unlock($1)", clusterSummaryViewRefreshLockID)
	}()

	for _, view := range clusterMVNames {
		if err := refreshView(ctx, db, view); err != nil {
			return fmt.Errorf("refresh %s: %w", view, err)
		}
	}

	refreshedAt := time.Now().UTC()
	return db.WithContext(ctx).Exec(`
		INSERT INTO materialized_view_refreshes (name, refreshed_at)
		VALUES (?, ?), (?, ?)
		ON CONFLICT (name)
		DO UPDATE SET refreshed_at = EXCLUDED.refreshed_at
	`, clusterSummaryViewName, refreshedAt, clusterImageViewName, refreshedAt).Error
}
