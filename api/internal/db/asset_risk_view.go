package db

import (
	"context"
	"fmt"
	"time"

	"gorm.io/gorm"
)

// assetRiskViewRefreshLockID guards refreshes of the asset_risk MV.
// Distinct from the SBOM and unified-vuln locks so a slow asset_risk
// refresh does not block a vuln refresh and vice versa.
const assetRiskViewRefreshLockID = 8_742_635_914

// assetRiskViewName is the materialized view holding per-asset triage
// signals (one row per (asset_type, asset_id)).
const assetRiskViewName = "asset_risk"

// AssetRiskRefreshDebounce exposes the asset_risk debounce window so
// the assetrisk trigger gate can schedule a trailing retry just past
// it when a trigger lands inside the window.
func AssetRiskRefreshDebounce() time.Duration { return assetRiskViewRefreshInterval }

// AssetRiskViewPopulated reports whether the asset_risk MV is
// populated. Used as a gate on the /api/triage endpoint so the brief
// startup window after a fresh deploy returns an empty triage list
// instead of a SQLSTATE 55000 error.
func AssetRiskViewPopulated(ctx context.Context, db *gorm.DB) (bool, error) {
	var populated bool
	err := db.WithContext(ctx).Raw(
		"SELECT COALESCE(bool_and(ispopulated), false) FROM pg_matviews WHERE matviewname = ?",
		assetRiskViewName,
	).Scan(&populated).Error
	return populated, err
}

// RefreshAssetRiskView refreshes the asset_risk MV under a dedicated
// advisory lock so concurrent triggers across replicas serialize.
// Reuses refreshView for the CONCURRENTLY+fallback logic that handles
// "view not yet populated" (first refresh after WITH NO DATA must be
// plain) gracefully. Returns ErrRefreshLockHeld when another process
// holds the lock so the caller can decide whether to retry or treat
// the in-flight refresh as good enough.
//
// The bool reports whether a REFRESH actually executed — false means
// the debounce window short-circuited. The assetrisk trigger gate uses
// it to schedule a trailing retry so a change that lands inside the
// debounce shadow still reaches the view once the window expires
// (triggers are rare now that upstream cascades are gated on actual
// refreshes, so a dropped trigger would otherwise stay stale until
// the next genuine upstream change).
func RefreshAssetRiskView(ctx context.Context, db *gorm.DB) (bool, error) {
	names := []string{assetRiskViewName}
	if materializedViewsRecentlyRefreshed(ctx, db, names, assetRiskViewRefreshInterval) {
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
	if err := conn.QueryRowContext(ctx, "SELECT pg_try_advisory_lock($1)", assetRiskViewRefreshLockID).Scan(&acquired); err != nil {
		return false, fmt.Errorf("acquire asset_risk refresh lock: %w", err)
	}
	if !acquired {
		return false, ErrRefreshLockHeld
	}
	// Release on a fresh ctx so a SIGTERM-triggered cancellation of
	// the parent ctx (mid-refresh) does not skip the unlock. Without
	// this, the PG backend retains the session-level advisory lock
	// when the conn is returned to the pool — every subsequent refresh
	// silently no-ops via ErrRefreshLockHeld. 5s budget is plenty for
	// a single one-row exec.
	defer func() {
		releaseCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, _ = conn.ExecContext(releaseCtx, "SELECT pg_advisory_unlock($1)", assetRiskViewRefreshLockID)
	}()

	if materializedViewsRecentlyRefreshed(ctx, db, names, assetRiskViewRefreshInterval) {
		return false, nil
	}

	if err := refreshView(ctx, db, assetRiskViewName); err != nil {
		return false, err
	}

	// Record the refresh time so the /api/triage handler can render
	// "data as of …" without a separate metadata table. No cheap
	// fingerprint — asset_risk joins a dozen sources — so "" disables
	// the source-version skip; cascade gating upstream is what keeps
	// its trigger rate proportional to actual change.
	return true, recordMaterializedViewRefresh(ctx, db, names, time.Now().UTC(), "")
}
