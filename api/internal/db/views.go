package db

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"gorm.io/gorm"
)

// ViewSchemaVersion tracks the SQL hash of each managed materialized view so
// that the view is only dropped and recreated when its definition changes.
type ViewSchemaVersion struct {
	Name string `gorm:"primaryKey"`
	Hash string
}

// sbomViewRefreshLockID is a stable advisory lock key used to ensure only one
// replica refreshes the SBOM materialized views at a time.
const sbomViewRefreshLockID = 8_742_635_912

// sbomComponentIndexGuardLockID serialises the ux_sbom_component_mv
// index swap in EnsureSbomComponentViewIndex across replicas.
const sbomComponentIndexGuardLockID = 8_742_635_914

// vulnUnifiedViewRefreshLockID guards refreshes of the unified vuln MVs
// (view_unified_repositories_vulnerabilities + view_unified_image_vulnerabilities).
// Distinct from the SBOM lock so a slow SBOM refresh does not block a
// vuln refresh and vice versa — the two view families are independent.
const vulnUnifiedViewRefreshLockID = 8_742_635_913

// Cross-replica debounce windows for background MV refresh triggers. The
// in-process gates coalesce bursts inside one pod, but daytime ingest can
// hit API + worker replicas at the same time; the materialized_view_refreshes
// table gives all replicas a shared "fresh enough" signal so they do not
// rebuild the same expensive MV family multiple times per short burst.
//
// The window is per-family and scaled to rebuild cost. A flat 30s was
// previously shared by every family, which pinned the DB rebuilding the
// expensive MVs almost continuously: sbom_metadata_view (~204s to rebuild)
// has no meaningful freshness to gain from a 30s cadence, it just spills to
// temp files and burns CPU. Cheap, interactively-read families stay tight;
// expensive families back off. These are dashboard views that tolerate
// minute-scale staleness.
const (
	// cluster_summary (~4.5s) + cluster_image_inventory (~2.5s) — backs
	// interactive cluster dashboards. 60s in practice meant rebuilding
	// around the clock (ingest never stops triggering); 2 minutes still
	// feels live on a dashboard while halving the steady-state rebuild
	// load. The source-version fingerprint skips the rebuild entirely
	// when cluster_record hasn't changed within the window.
	clusterViewRefreshInterval = 2 * time.Minute
	// host_exposure (~0.2s) + exposed_digests (~11s) share one lock/window;
	// follows the expensive member, not the cheap one.
	hostExposureViewRefreshInterval = 5 * time.Minute
	// asset_risk (~15s), cascaded from the vuln + host-exposure + dep-health
	// + secret-probe paths, so it is the most-triggered family.
	assetRiskViewRefreshInterval = 5 * time.Minute
	// Four unified/canonical vuln MVs; view_unified_image_vulnerabilities
	// alone is ~33s to rebuild.
	vulnUnifiedViewRefreshInterval = 5 * time.Minute
	// sbom_metadata_view (~204s) + sbom_component_view — by far the most
	// expensive family; SBOM metadata changes slowly so a long window is fine.
	sbomViewRefreshInterval = 15 * time.Minute
)

// Maximum age of the last actual refresh for the source-fingerprint
// skip to apply (see materializedViewsSourceUnchanged). The cluster-
// derived families display received_at-based last_seen values that the
// fingerprint ignores, so they refresh at least this often regardless;
// the SBOM family's fingerprint fully determines its change-relevant
// contents (repo renames excepted), so it gets a long safety cap.
const (
	clusterDerivedViewMaxSkipAge = 30 * time.Minute
	sbomViewMaxSkipAge           = 6 * time.Hour
)

// vulnUnifiedViewNames are the materialized views that hold the unified
// per-asset vulnerability rows the API filters and groups against, plus
// the two canonical MVs that ride on top of them.
//
// Refresh order matters and matches slice order:
//   1. view_unified_repositories_vulnerabilities
//   2. view_unified_image_vulnerabilities
//   3. vuln_canonical_assets    (depends on #1 and #2 + vuln_metadata)
//   4. vuln_canonical_summary   (depends on #3 + cisa_kev_entries + epss_entries)
//
// All four share the same advisory lock and freshness debounce window so
// scan-completion triggers can't ladder them up out-of-order against
// mismatched snapshots.
var vulnUnifiedViewNames = []string{
	"view_unified_repositories_vulnerabilities",
	"view_unified_image_vulnerabilities",
	"vuln_canonical_assets",
	"vuln_canonical_summary",
}

// vulnCanonicalViewNames is the subset of vulnUnifiedViewNames that the
// canonical-summary MVs comprise. Read-side gates (VulnCanonicalViewsPopulated)
// use this to decide whether the admin /api/vuln/list path can hit the
// summary MV directly or must fall back to the per-asset view + group
// at request time.
var vulnCanonicalViewNames = []string{
	"vuln_canonical_assets",
	"vuln_canonical_summary",
}

// EnsureViews applies SQL view definitions from the provided file paths.
// Each file is hashed; the view is only dropped and recreated when the hash
// differs from what is stored in view_schema_versions. A PostgreSQL advisory
// lock serialises concurrent replicas so only one does the work.
//
// The hash is checked once *outside* the advisory lock so the common
// "nothing changed" case (every boot after the first deploy of a given
// migration) doesn't compete for the lock at all. This matters because
// the lock is held for the whole DDL transaction — a stuck rolling
// deploy or a leftover idle-in-transaction backend can otherwise block
// new replicas indefinitely. With the fast-path skip, only replicas
// that actually need to do work serialise on the lock.
// viewLockRetryDelay paces the busy-wait between advisory-lock attempts.
// Short enough to feel responsive, long enough that polling doesn't pile
// up against the DB while another replica is mid-migration.
const viewLockRetryDelay = 2 * time.Second

// viewLockMaxWaitTime caps how long a replica polls for a single
// migration's advisory lock before bailing. Used as a guardrail —
// migrations should run in seconds; if one is genuinely held for >5min
// something is stuck and the next bootstrap attempt is the right move.
const viewLockMaxWaitTime = 5 * time.Minute

func EnsureViews(ctx context.Context, db *gorm.DB, paths ...string) error {
	for _, path := range paths {
		payload, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read view sql %s: %w", path, err)
		}
		if len(payload) == 0 {
			continue
		}
		hash := fmt.Sprintf("%x", sha256.Sum256(payload))
		declared := extractMatviewNames(payload)

		// Fast path: stored hash matches AND every materialized view the
		// migration declares is still present in pg_matviews. The MV
		// existence check guards against a CASCADE drop in an unrelated
		// later migration leaving this file's outputs gone while its hash
		// still appears applied — without it, EnsureViews silently skips
		// the recreate forever and background refreshes loop with
		// "relation does not exist". The recheck inside the lock below
		// still runs for races (two replicas both decide to do work).
		var stored ViewSchemaVersion
		if err := db.WithContext(ctx).First(&stored, "name = ?", path).Error; err == nil && stored.Hash == hash {
			ok, mverr := matviewsExist(ctx, db, declared)
			if mverr == nil && ok {
				continue
			}
			if mverr != nil {
				log.Printf("ensure view %s: matview existence check failed, will reapply: %v", path, mverr)
			} else {
				log.Printf("ensure view %s: declared matview(s) missing, will reapply: %v", path, declared)
			}
		}

		if err := applyViewWithRetry(ctx, db, path, payload, hash); err != nil {
			return fmt.Errorf("ensure view %s: %w", path, err)
		}
	}
	return nil
}

// createMatviewRE matches `CREATE MATERIALIZED VIEW [IF NOT EXISTS] <name>`.
// Used by extractMatviewNames to discover what each migration's body
// creates so EnsureViews can verify the MVs still exist even when the
// stored hash matches.
var createMatviewRE = regexp.MustCompile(`(?i)CREATE\s+MATERIALIZED\s+VIEW\s+(?:IF\s+NOT\s+EXISTS\s+)?([a-zA-Z_][a-zA-Z0-9_]*)`)

// extractMatviewNames returns the set of materialized-view names the
// SQL payload declares with CREATE MATERIALIZED VIEW. Comment lines
// (anything after `--` on a line) are stripped first so a commented-
// out example doesn't get treated as a real declaration.
func extractMatviewNames(payload []byte) []string {
	scrubbed := stripSQLLineComments(string(payload))
	matches := createMatviewRE.FindAllStringSubmatch(scrubbed, -1)
	if len(matches) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(matches))
	names := make([]string, 0, len(matches))
	for _, m := range matches {
		n := strings.ToLower(m[1])
		if _, dup := seen[n]; dup {
			continue
		}
		seen[n] = struct{}{}
		names = append(names, n)
	}
	return names
}

// stripSQLLineComments removes everything after `--` on each line.
// Cheap and good-enough for migration-file scanning: we don't care
// about quoted strings since CREATE MATERIALIZED VIEW <name> isn't a
// pattern that naturally appears inside SQL literals in this codebase.
func stripSQLLineComments(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, line := range strings.Split(s, "\n") {
		if idx := strings.Index(line, "--"); idx >= 0 {
			line = line[:idx]
		}
		b.WriteString(line)
		b.WriteByte('\n')
	}
	return b.String()
}

// matviewsExist reports whether every name in `names` is present in
// pg_matviews. Returns true for an empty slice (no expectations to
// verify). Used by EnsureViews to detect migrations whose outputs got
// CASCADE-dropped by a later migration without that later migration
// itself being re-run.
func matviewsExist(ctx context.Context, db *gorm.DB, names []string) (bool, error) {
	if len(names) == 0 {
		return true, nil
	}
	var count int64
	if err := db.WithContext(ctx).Raw(
		"SELECT COUNT(*) FROM pg_matviews WHERE matviewname IN (?)",
		names,
	).Scan(&count).Error; err != nil {
		return false, err
	}
	return int(count) == len(names), nil
}

// applyViewWithRetry runs a single migration under a try-then-poll
// pattern on its advisory lock. The previous implementation used the
// blocking pg_advisory_xact_lock, which deadlocked multi-replica
// rollouts: replica A holds the migration lock while its DROP waits on
// an in-flight REFRESH's AccessExclusiveLock; replica B's bootstrap
// blocks on the advisory lock waiting for A; K8s eventually kills B
// before A finishes and the cluster loops with "context canceled".
//
// The fix is to never block the connection — try the lock, give up
// immediately if held, sleep and retry. On every iteration we re-check
// the stored hash so as soon as A commits, B exits cleanly with a
// match. The 5-minute wall-clock cap stops a runaway migration from
// holding bootstrap forever; on timeout the bootstrap fails fast and
// the next pod restart picks up cleanly.
func applyViewWithRetry(ctx context.Context, db *gorm.DB, path string, payload []byte, hash string) error {
	sum := sha256.Sum256([]byte(path))
	lockKey := int64(binary.BigEndian.Uint64(sum[:8]))
	deadline := time.Now().Add(viewLockMaxWaitTime)

	for {
		// Re-check stored hash before every attempt. If another
		// replica just finished applying, we're done — no need to
		// even try the lock.
		var stored ViewSchemaVersion
		if err := db.WithContext(ctx).First(&stored, "name = ?", path).Error; err == nil && stored.Hash == hash {
			return nil
		}

		applied, err := tryApplyView(ctx, db, lockKey, path, payload, hash)
		if err != nil {
			return err
		}
		if applied {
			return nil
		}

		// Lock held by another replica. Sleep and retry, respecting
		// ctx cancellation and the wall-clock cap.
		if time.Now().After(deadline) {
			return fmt.Errorf("timed out after %s waiting for migration lock on %s", viewLockMaxWaitTime, path)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(viewLockRetryDelay):
		}
	}
}

// tryApplyView is the single-attempt body. Returns (true, nil) on
// successful apply OR same-hash skip; (false, nil) if the lock was
// held by another replica; (false, err) on any execution failure.
func tryApplyView(ctx context.Context, db *gorm.DB, lockKey int64, path string, payload []byte, hash string) (bool, error) {
	applied := false
	declared := extractMatviewNames(payload)
	err := db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var acquired bool
		if err := tx.Raw("SELECT pg_try_advisory_xact_lock(?)", lockKey).Scan(&acquired).Error; err != nil {
			return fmt.Errorf("try advisory lock: %w", err)
		}
		if !acquired {
			return nil // another replica holds the lock; outer loop retries
		}

		// Re-check inside the lock — another replica might have
		// committed a matching hash between our outer check and here.
		// The MV existence check mirrors the fast-path: if a sibling
		// replica recorded our hash but the declared MVs are gone
		// (CASCADE drop in an unrelated migration), we still need to
		// reapply.
		var stored ViewSchemaVersion
		result := tx.First(&stored, "name = ?", path)
		if result.Error == nil && stored.Hash == hash {
			ok, mverr := matviewsExist(ctx, tx, declared)
			if mverr == nil && ok {
				applied = true
				return nil
			}
		}

		if err := tx.Exec(string(payload)).Error; err != nil {
			return fmt.Errorf("exec view sql %s: %w", path, err)
		}

		if err := tx.Save(&ViewSchemaVersion{Name: path, Hash: hash}).Error; err != nil {
			return err
		}
		applied = true
		return nil
	})
	return applied, err
}

// EnsureSbomComponentViewIndex re-asserts the plain-column unique index
// that REFRESH MATERIALIZED VIEW CONCURRENTLY requires on
// sbom_component_view. The canonical view-definition migration
// (20260311_fix_sbom_component_view_implicit_root.sql) carries the
// original COALESCE expression index, which disqualifies the view from
// CONCURRENTLY; 20260612_fix_sbom_component_view_unique_index.sql swaps
// it for a plain-column one, but hash-gated migrations run once — so any
// path that re-applies the 20260311 file (a future edit, or EnsureViews'
// missing-matview recovery after a CASCADE drop) would silently restore
// the broken index and background refreshes would start failing again.
// The 20260311 file itself can't be edited to carry the fix: changing
// its hash re-applies it everywhere, which both forces a full rebuild
// of the view family and replays a stale plain-view definition of
// view_unified_repositories_vulnerabilities over the materialized one
// from 20260430.
//
// Call after EnsureViews (so a just-recreated view gets fixed before the
// first refresh) and before EnsureViewsPopulated. Healthy boots cost one
// catalog read. The advisory try-lock keeps concurrent replicas from
// racing the DROP/CREATE; losers skip — the winner's commit is enough.
func EnsureSbomComponentViewIndex(ctx context.Context, db *gorm.DB) error {
	broken, err := sbomComponentIndexBroken(ctx, db)
	if err != nil || !broken {
		return err
	}
	return db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var acquired bool
		if err := tx.Raw("SELECT pg_try_advisory_xact_lock(?)", sbomComponentIndexGuardLockID).Scan(&acquired).Error; err != nil {
			return fmt.Errorf("try index guard lock: %w", err)
		}
		if !acquired {
			return nil // another replica is mid-swap
		}
		// Re-check under the lock — the winning replica may have already
		// committed the swap between our first check and here.
		broken, err := sbomComponentIndexBroken(ctx, tx)
		if err != nil || !broken {
			return err
		}
		log.Printf("sbom_component_view: replacing CONCURRENTLY-incompatible unique index")
		if err := tx.Exec("DROP INDEX IF EXISTS ux_sbom_component_mv").Error; err != nil {
			return fmt.Errorf("drop expression index: %w", err)
		}
		return tx.Exec(`
			CREATE UNIQUE INDEX ux_sbom_component_mv
			  ON sbom_component_view (sbom_id, asset_type, asset_ref_id, component_ref)
			  NULLS NOT DISTINCT
		`).Error
	})
}

// sbomComponentIndexBroken reports whether sbom_component_view exists
// but its unique index is missing or is the COALESCE expression variant
// that REFRESH CONCURRENTLY rejects. A missing view is not "broken" —
// EnsureViews owns creating it.
func sbomComponentIndexBroken(ctx context.Context, db *gorm.DB) (bool, error) {
	var viewExists bool
	if err := db.WithContext(ctx).Raw(
		"SELECT EXISTS (SELECT 1 FROM pg_matviews WHERE matviewname = 'sbom_component_view')",
	).Scan(&viewExists).Error; err != nil {
		return false, fmt.Errorf("check sbom_component_view exists: %w", err)
	}
	if !viewExists {
		return false, nil
	}
	var indexdef string
	if err := db.WithContext(ctx).Raw(`
		SELECT COALESCE(
			(SELECT indexdef FROM pg_indexes
			 WHERE schemaname = 'public' AND indexname = 'ux_sbom_component_mv'),
			'')
	`).Scan(&indexdef).Error; err != nil {
		return false, fmt.Errorf("read ux_sbom_component_mv indexdef: %w", err)
	}
	return indexdef == "" || strings.Contains(indexdef, "COALESCE"), nil
}

// EnsureViewsPopulated blocks until all SBOM materialized views are populated.
// It must be called at startup before the HTTP server begins serving traffic.
// One replica performs the refresh; others poll until it completes.
// The refresh itself runs under context.Background() so a SIGTERM does not abort
// it mid-way; the caller's ctx is only used for the polling loop. This means a
// SIGTERM during an in-progress refresh will wait for it to finish before the
// server shuts down.
func EnsureViewsPopulated(ctx context.Context, db *gorm.DB) error {
	refreshCtx := context.Background()
	for {
		populated, err := viewsPopulated(ctx, db)
		if err != nil {
			return err
		}
		if populated {
			return nil
		}

		// Try to be the replica that does the refresh. Transaction-scoped advisory
		// lock ensures the same connection is used for lock + refresh + unlock.
		if err := db.WithContext(refreshCtx).Transaction(func(tx *gorm.DB) error {
			var acquired bool
			if err := tx.Raw("SELECT pg_try_advisory_xact_lock(?)", sbomViewRefreshLockID).Scan(&acquired).Error; err != nil || !acquired {
				return nil // another replica is refreshing, we will poll
			}
			if err := tx.Exec("REFRESH MATERIALIZED VIEW sbom_component_view").Error; err != nil {
				return fmt.Errorf("refresh sbom_component_view: %w", err)
			}
			if err := tx.Exec("REFRESH MATERIALIZED VIEW sbom_metadata_view").Error; err != nil {
				return fmt.Errorf("refresh sbom_metadata_view: %w", err)
			}
			refreshedAt := time.Now().UTC()
			if err := tx.Exec(`
				INSERT INTO materialized_view_refreshes (name, refreshed_at)
				VALUES ('sbom_component_view', ?), ('sbom_metadata_view', ?)
				ON CONFLICT (name) DO UPDATE SET refreshed_at = EXCLUDED.refreshed_at
			`, refreshedAt, refreshedAt).Error; err != nil {
				return fmt.Errorf("record refresh time: %w", err)
			}
			return nil
		}); err != nil {
			log.Printf("populate views: %v", err)
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
}

// refreshView refreshes a single materialized view. It checks the view's own
// ispopulated flag to decide between CONCURRENTLY (non-blocking) and a plain
// refresh (required when the view has never been populated). If CONCURRENTLY
// fails with SQLSTATE 55000 (object not in prerequisite state — view not yet
// populated or no unique index), it falls back to a plain refresh so a race
// between EnsureViews recreating the view and this function doesn't cause
// permanent job failures.
//
// JIT is disabled per-connection before issuing the REFRESH. Measured on a
// representative dataset, JIT compile of the asset_risk MV body alone cost
// ~4.8s of an 11.3s execution; the MV is a one-shot CTE-heavy query so the
// compile cost never amortises. Small queries don't hit jit_above_cost so
// turning it off on the conn doesn't penalise other workloads — the conn
// returns to the pool with jit=off, which is benign.
func refreshView(ctx context.Context, db *gorm.DB, view string) error {
	sqlDB, err := db.WithContext(ctx).DB()
	if err != nil {
		return fmt.Errorf("get raw db: %w", err)
	}
	conn, err := sqlDB.Conn(ctx)
	if err != nil {
		return fmt.Errorf("acquire db connection: %w", err)
	}
	defer conn.Close()

	if _, err := conn.ExecContext(ctx, "SET jit = off"); err != nil {
		log.Printf("disable JIT for %s refresh: %v", view, err)
	}

	// These MV bodies sort/hash hundreds of millions of rows and spill far
	// past the default work_mem to temp files (observed in the TB range of
	// temp_bytes across refreshes). Raise work_mem for just this refresh so
	// the big sort/hash nodes stay in memory, then RESET before the conn
	// returns to the pool — unlike jit=off, a fat work_mem left on a pooled
	// conn would inflate every subsequent query's per-node memory budget.
	if _, err := conn.ExecContext(ctx, "SET work_mem = '256MB'"); err != nil {
		log.Printf("raise work_mem for %s refresh: %v", view, err)
	} else {
		defer func() {
			resetCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_, _ = conn.ExecContext(resetCtx, "RESET work_mem")
		}()
	}

	var populated bool
	_ = conn.QueryRowContext(ctx,
		"SELECT COALESCE(ispopulated, false) FROM pg_matviews WHERE matviewname = $1", view,
	).Scan(&populated)

	if populated {
		_, err := conn.ExecContext(ctx, "REFRESH MATERIALIZED VIEW CONCURRENTLY "+view)
		if err == nil {
			return nil
		}
		// SQLSTATE 55000 covers two distinct situations and only one of
		// them may fall through to a plain refresh:
		//
		//   1. EnsureViews recreated the view WITH NO DATA between our
		//      ispopulated read and the REFRESH — the view is actually
		//      unpopulated, readers are excluded by the populated gates,
		//      and a plain refresh is the required first populate.
		//   2. The view IS populated but lacks the unique index
		//      CONCURRENTLY needs (a migration bug). A plain refresh
		//      here would take an ACCESS EXCLUSIVE lock and block every
		//      reader for the full rebuild — minutes for the big MVs —
		//      which surfaces as the whole app hanging. Surface the
		//      error instead; stale-but-readable beats blocked.
		//
		// Distinguish by re-reading ispopulated after the failure.
		if !isSQLState(err, "55000") {
			return err
		}
		var stillPopulated bool
		_ = conn.QueryRowContext(ctx,
			"SELECT COALESCE(ispopulated, false) FROM pg_matviews WHERE matviewname = $1", view,
		).Scan(&stillPopulated)
		if stillPopulated {
			return fmt.Errorf("refresh %s: CONCURRENTLY failed (55000) on a populated view — missing unique index? refusing blocking plain refresh: %w", view, err)
		}
		log.Printf("CONCURRENTLY failed for %s (recreated WITH NO DATA), running first-populate plain refresh", view)
	}
	_, err = conn.ExecContext(ctx, "REFRESH MATERIALIZED VIEW "+view)
	return err
}

// recordMaterializedViewRefresh upserts a refreshed_at row in
// materialized_view_refreshes for each name in the slice. Single
// source of truth so a future view added to any of the multi-MV
// refresher lists (cluster_summary, host_exposure, vuln_unified)
// can't silently miss its timestamp record — the previous pattern
// hardcoded VALUES (?, ?), (?, ?) tuples positional to a slice and
// would only catch the bug at runtime via a stuck debounce window.
//
// sourceVersion is the family's source fingerprint captured *before*
// the refresh started (so changes that land mid-refresh produce a
// mismatch on the next trigger instead of being lost). Families
// without a cheap fingerprint pass "" — the empty string never
// matches in materializedViewsSourceUnchanged, so they refresh on
// every debounce-expired trigger exactly as before.
func recordMaterializedViewRefresh(ctx context.Context, db *gorm.DB, names []string, at time.Time, sourceVersion string) error {
	if len(names) == 0 {
		return nil
	}
	placeholders := strings.TrimRight(strings.Repeat("(?,?,?),", len(names)), ",")
	args := make([]any, 0, len(names)*3)
	for _, n := range names {
		args = append(args, n, at, sourceVersion)
	}
	return db.WithContext(ctx).Exec(`
		INSERT INTO materialized_view_refreshes (name, refreshed_at, source_version)
		VALUES `+placeholders+`
		ON CONFLICT (name)
		DO UPDATE SET refreshed_at = EXCLUDED.refreshed_at,
		              source_version = EXCLUDED.source_version
	`, args...).Error
}

// materializedViewsSourceVersionMatches reports whether every view in
// `names` is populated and recorded the exact same source fingerprint
// at its last refresh — i.e. a rebuild would reproduce the current
// change-relevant contents byte-for-byte.
//
// Callers combine this with materializedViewsRecentlyRefreshed under
// the family's max-skip age to decide whether to skip the REFRESH:
// the fingerprint deliberately ignores heartbeat columns (the
// cluster-derived views expose received_at as a user-facing
// "Last seen X ago"), so an unbounded skip would make healthy-but-
// quiet clusters look dead overnight. The age cap forces a periodic
// backstop refresh; skips never bump refreshed_at so the cap measures
// actual refresh age.
//
// current == "" (fingerprint query failed, or family doesn't
// fingerprint) always returns false — fail open into a refresh.
func materializedViewsSourceVersionMatches(ctx context.Context, db *gorm.DB, names []string, current string) bool {
	if current == "" || len(names) == 0 {
		return false
	}
	placeholders := strings.TrimRight(strings.Repeat("?,", len(names)), ",")
	args := make([]any, 0, len(names)+1)
	for _, name := range names {
		args = append(args, name)
	}
	args = append(args, current)

	var matched int64
	err := db.WithContext(ctx).Raw(`
		SELECT COUNT(*)
		FROM materialized_view_refreshes r
		JOIN pg_matviews m ON m.matviewname = r.name
		WHERE r.name IN (`+placeholders+`)
		  AND r.source_version = ?
		  AND m.ispopulated
	`, args...).Scan(&matched).Error
	return err == nil && matched == int64(len(names))
}

// clusterRecordSourceVersion fingerprints cluster_record, the sole
// high-churn source behind cluster_summary, cluster_image_inventory,
// host_exposure, and exposed_digests. Ingest bumps last_change_at only
// when a record's state actually changed (insert, content change, or
// tombstone), so an unchanged max means a rebuild would be a no-op.
// Backed by ix_cluster_record_last_change_at as an index-tail scan.
//
// Deliberately ignores the tiny `clusters` name-metadata table — a ROR
// rename changes display strings only and gets picked up by the next
// genuine record change. Returns "" (never skip) on query failure.
func clusterRecordSourceVersion(ctx context.Context, db *gorm.DB) string {
	var v string
	if err := db.WithContext(ctx).Raw(
		"SELECT COALESCE(MAX(last_change_at)::text, 'empty') FROM cluster_record",
	).Scan(&v).Error; err != nil {
		log.Printf("cluster_record source version: %v", err)
		return ""
	}
	return v
}

// sbomSourceVersion fingerprints the SBOM view family's mutable
// sources: sboms, sbom_bindings, and repo_commits are append-only on
// the paths the views read (a rebind always rides on a new sboms row),
// so max(created_at) per table captures every change the views can
// observe. All three maxes are index-tail or small-table scans.
func sbomSourceVersion(ctx context.Context, db *gorm.DB) string {
	var v string
	if err := db.WithContext(ctx).Raw(`
		SELECT COALESCE((SELECT MAX(created_at) FROM sboms)::text, 'empty')
		    || '|' || COALESCE((SELECT MAX(created_at) FROM sbom_bindings)::text, 'empty')
		    || '|' || COALESCE((SELECT MAX(created_at) FROM repo_commits)::text, 'empty')
	`).Scan(&v).Error; err != nil {
		log.Printf("sbom source version: %v", err)
		return ""
	}
	return v
}

func materializedViewsRecentlyRefreshed(ctx context.Context, db *gorm.DB, names []string, maxAge time.Duration) bool {
	if maxAge <= 0 || len(names) == 0 {
		return false
	}

	placeholders := strings.TrimRight(strings.Repeat("?,", len(names)), ",")
	args := make([]any, 0, len(names)+1)
	for _, name := range names {
		args = append(args, name)
	}
	args = append(args, time.Now().UTC().Add(-maxAge))

	var freshCount int64
	err := db.WithContext(ctx).Raw(`
		SELECT COUNT(*)
		FROM materialized_view_refreshes r
		JOIN pg_matviews m ON m.matviewname = r.name
		WHERE r.name IN (`+placeholders+`)
		  AND r.refreshed_at >= ?
		  AND m.ispopulated
	`, args...).Scan(&freshCount).Error
	return err == nil && freshCount == int64(len(names))
}

// isSQLState reports whether err contains a PostgreSQL error with the given
// five-character SQLSTATE code.
func isSQLState(err error, code string) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == code
}

func viewsPopulated(ctx context.Context, db *gorm.DB) (bool, error) {
	var populated bool
	err := db.WithContext(ctx).Raw(
		"SELECT COALESCE(bool_and(ispopulated), false) FROM pg_matviews WHERE matviewname IN ('sbom_component_view', 'sbom_metadata_view')",
	).Scan(&populated).Error
	return populated, err
}

// ErrRefreshLockHeld is returned by RefreshMaterializedViews when another
// process holds the advisory lock. Callers should treat this as a transient
// condition and retry rather than silently succeeding.
var ErrRefreshLockHeld = errors.New("materialized view refresh lock held by another process")

// VulnUnifiedViewsPopulated reports whether the two per-finding unified
// vuln MVs are populated. Used as a gate on read endpoints that read
// those views directly (or via vuln_canonical_assets, which always
// populates after they do).
//
// Note: this intentionally does NOT check the two canonical MVs. The
// canonical-summary read-path has its own gate (VulnCanonicalViewsPopulated)
// because callers can fall back to the per-finding views when the
// canonical MVs are still cold.
func VulnUnifiedViewsPopulated(ctx context.Context, db *gorm.DB) (bool, error) {
	var populated bool
	err := db.WithContext(ctx).Raw(
		"SELECT COALESCE(bool_and(ispopulated), false) FROM pg_matviews WHERE matviewname IN (?, ?)",
		"view_unified_repositories_vulnerabilities", "view_unified_image_vulnerabilities",
	).Scan(&populated).Error
	return populated, err
}

// VulnCanonicalViewsPopulated reports whether both canonical vuln MVs
// (vuln_canonical_assets + vuln_canonical_summary) are populated.
// LoadListPage / computeSummary use this to choose between the fast
// pre-aggregated path and the slower fallback that re-aggregates from
// view_unified_*_vulnerabilities at request time.
func VulnCanonicalViewsPopulated(ctx context.Context, db *gorm.DB) (bool, error) {
	var populated bool
	err := db.WithContext(ctx).Raw(
		"SELECT COALESCE(bool_and(ispopulated), false) FROM pg_matviews WHERE matviewname IN (?, ?)",
		vulnCanonicalViewNames[0], vulnCanonicalViewNames[1],
	).Scan(&populated).Error
	return populated, err
}

// RefreshVulnUnifiedViews refreshes the unified vuln MVs under a
// dedicated advisory lock so concurrent triggers across replicas
// serialize. Reuses refreshView for the CONCURRENTLY+fallback logic
// that handles "view not yet populated" (first refresh after WITH NO
// DATA must be plain) gracefully. Returns ErrRefreshLockHeld when
// another process holds the lock so the caller can decide whether to
// retry or treat the in-flight refresh as good enough.
//
// The bool reports whether a REFRESH actually executed — false means
// the debounce window short-circuited (or another replica held the
// lock). vulnmetrics uses it to cascade asset_risk only when the MVs
// it reads actually changed, instead of laddering asset_risk up to
// its own debounce floor on every no-op trigger.
func RefreshVulnUnifiedViews(ctx context.Context, db *gorm.DB) (bool, error) {
	if materializedViewsRecentlyRefreshed(ctx, db, vulnUnifiedViewNames, vulnUnifiedViewRefreshInterval) {
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
	if err := conn.QueryRowContext(ctx, "SELECT pg_try_advisory_lock($1)", vulnUnifiedViewRefreshLockID).Scan(&acquired); err != nil {
		return false, fmt.Errorf("acquire vuln refresh lock: %w", err)
	}
	if !acquired {
		return false, ErrRefreshLockHeld
	}
	// See note on RefreshAssetRiskView — release must survive a
	// caller ctx cancellation or the session-level advisory lock
	// leaks back into the pool.
	defer func() {
		releaseCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, _ = conn.ExecContext(releaseCtx, "SELECT pg_advisory_unlock($1)", vulnUnifiedViewRefreshLockID)
	}()

	if materializedViewsRecentlyRefreshed(ctx, db, vulnUnifiedViewNames, vulnUnifiedViewRefreshInterval) {
		return false, nil
	}

	for _, view := range vulnUnifiedViewNames {
		if err := refreshView(ctx, db, view); err != nil {
			return false, fmt.Errorf("refresh %s: %w", view, err)
		}
	}

	// No cheap fingerprint for this family (its sources span the scan
	// result, VEX, metadata, EPSS and KEV tables) — pass "" so the
	// fingerprint skip never fires and the debounce window remains the
	// only rate limit, same as before.
	return true, recordMaterializedViewRefresh(ctx, db, vulnUnifiedViewNames, time.Now().UTC(), "")
}

// RefreshMaterializedViews refreshes SBOM materialized views and records refresh time.
// It uses a PostgreSQL advisory lock so that in a multi-replica deployment only one
// instance performs the refresh at a time. If the lock is already held, it returns
// ErrRefreshLockHeld so the caller can retry after the current refresh completes.
// CONCURRENTLY is used so reads are not blocked during the refresh, but it must run
// outside a transaction block, so a session-level advisory lock is used instead.
func RefreshMaterializedViews(ctx context.Context, db *gorm.DB) error {
	sbomViewNames := []string{"sbom_metadata_view", "sbom_component_view"}
	if materializedViewsRecentlyRefreshed(ctx, db, sbomViewNames, sbomViewRefreshInterval) {
		return nil
	}

	// Capture the source fingerprint before refreshing so anything that
	// lands mid-refresh mismatches on the next trigger. If nothing
	// changed since the last refresh, skip the rebuild — this family is
	// by far the most expensive (sbom_metadata_view re-parses every
	// SBOM document) and SBOMs arrive in CI bursts, so most off-peak
	// triggers are no-ops.
	sourceVersion := sbomSourceVersion(ctx, db)
	if materializedViewsSourceVersionMatches(ctx, db, sbomViewNames, sourceVersion) &&
		materializedViewsRecentlyRefreshed(ctx, db, sbomViewNames, sbomViewMaxSkipAge) {
		return nil
	}

	// Session-level advisory lock: must acquire and release on the same connection.
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
	if err := conn.QueryRowContext(ctx, "SELECT pg_try_advisory_lock($1)", sbomViewRefreshLockID).Scan(&acquired); err != nil {
		return fmt.Errorf("acquire refresh lock: %w", err)
	}
	if !acquired {
		log.Printf("refresh lock held by another process, will retry")
		return ErrRefreshLockHeld
	}
	// See note on RefreshAssetRiskView — release must survive a
	// caller ctx cancellation or the session-level advisory lock
	// leaks back into the pool.
	defer func() {
		releaseCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, _ = conn.ExecContext(releaseCtx, "SELECT pg_advisory_unlock($1)", sbomViewRefreshLockID)
	}()

	if materializedViewsRecentlyRefreshed(ctx, db, sbomViewNames, sbomViewRefreshInterval) {
		return nil
	}

	// Refresh metadata first so that any SBOM visible in sbom_metadata_view is
	// guaranteed to already have its components in sbom_component_view (which
	// takes a later snapshot). Reversing this order would cause recent SBOMs
	// committed between the two snapshot times to show component_count = 0.
	for _, view := range sbomViewNames {
		if err := refreshView(ctx, db, view); err != nil {
			return fmt.Errorf("refresh %s: %w", view, err)
		}
	}

	if err := recordMaterializedViewRefresh(ctx, db, sbomViewNames, time.Now().UTC(), sourceVersion); err != nil {
		return fmt.Errorf("record refresh: %w", err)
	}

	return nil
}
