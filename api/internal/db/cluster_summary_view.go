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

const clusterSummaryViewName = "cluster_summary"

// ClusterSummaryViewPopulated reports whether the cluster_summary MV is
// populated. Used as a gate on ClusterSummaryHandler so the brief
// startup window after a fresh deploy returns an empty list (and kicks
// a refresh) instead of a SQLSTATE 55000 error.
func ClusterSummaryViewPopulated(ctx context.Context, db *gorm.DB) (bool, error) {
	var populated bool
	err := db.WithContext(ctx).Raw(
		"SELECT COALESCE(bool_and(ispopulated), false) FROM pg_matviews WHERE matviewname = ?",
		clusterSummaryViewName,
	).Scan(&populated).Error
	return populated, err
}

// RefreshClusterSummaryView refreshes the cluster_summary MV under a
// dedicated session-level advisory lock so concurrent triggers across
// replicas serialise. Reuses refreshView for the CONCURRENTLY+fallback
// logic that handles "view not yet populated" gracefully. Returns
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

	if err := refreshView(ctx, db, clusterSummaryViewName); err != nil {
		return err
	}

	refreshedAt := time.Now().UTC()
	return db.WithContext(ctx).Exec(`
		INSERT INTO materialized_view_refreshes (name, refreshed_at)
		VALUES (?, ?)
		ON CONFLICT (name)
		DO UPDATE SET refreshed_at = EXCLUDED.refreshed_at
	`, clusterSummaryViewName, refreshedAt).Error
}
