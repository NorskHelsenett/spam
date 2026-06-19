package vulnmetrics

import (
	"context"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"log"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/NorskHelsenett/spam/internal/assetrisk"
	"github.com/NorskHelsenett/spam/internal/cache"
	spamdb "github.com/NorskHelsenett/spam/internal/db"
	"github.com/NorskHelsenett/spam/internal/vulnmeta"
	"gorm.io/gorm"
)

const (
	summaryCacheKey = "vuln:summary:v1"
	reposCacheKey   = "vuln:repos:v1"
	facetsCacheKey  = "vuln:facets:v1"
	// Bump the prefix when the list ORDER BY or shape changes — the
	// summaryVersion only tracks data freshness, so old entries would
	// keep serving the previous ordering until their 7-day TTL. v6:
	// summaryVersion changed shape (MV-refresh watermark), so the hashed
	// key differs; bump so no v5 entry is ever consulted.
	listCachePrefix = "vuln:list:v6:"
	// Per-subject scoped caches. Like the list cache they embed the
	// caller's ACL fragments + args in the hashed key and are versioned
	// on the MV-refresh watermark, so two callers with identical readable
	// sets share an entry and every entry invalidates exactly when the
	// vuln MVs rebuild. v1: introduced when the scoped summary/trend paths
	// moved onto vuln_canonical_assets.
	summaryScopedCachePrefix = "vuln:summaryscoped:v1:"
	trendScopedCachePrefix   = "vuln:trendscoped:v1:"
	summaryCacheTTL          = 7 * 24 * time.Hour
	// refreshMaxRuntime must outlast the worst-case contended rebuild of
	// all four unified/canonical vuln MVs, not just the uncontended ~40s.
	// If it fires mid-refresh the debounce timestamp never gets recorded
	// and the family re-runs on every trigger — the storm that starved
	// the DB on 2026-06. Sized to catch a true hang, not a slow refresh.
	refreshMaxRuntime = 20 * time.Minute
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
	Type   string `json:"type"`
	ID     string `json:"id"`
	Slug   string `json:"slug"`
	Digest string `json:"digest,omitempty"`
}

// VulnGroup is one row in the /api/vuln/list response: a single CVE /
// advisory rolled up across every asset it was found on. Fields like
// pkg_name / installed_version come from the worst-severity row
// contributing to the group, which is almost always stable across
// sources for the same advisory.
//
// Aliases is populated from vuln_metadata when an enrichment row
// exists — lets the UI show cross-references (e.g. CVE-* ↔ GHSA-* ↔
// BIT-*) and lets search queries find a row by any of its known
// identifiers.
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
	Aliases          []string    `json:"aliases,omitempty"`
	RepoCount        int         `json:"repo_count"`
	ImageCount       int         `json:"image_count"`

	// Exploitation signals from the bulk feeds. KEVKnown is the
	// authoritative "actually exploited in the wild" flag; EPSSScore
	// (0-1) and EPSSPercentile (0-1) come from FIRST.org's daily
	// model. Both are 0 / false when neither feed has the CVE — the
	// API always returns the fields so clients can render badges
	// without a presence check.
	KEVKnown           bool       `json:"kev_known"`
	KEVKnownRansomware bool       `json:"kev_known_ransomware"`
	KEVDateAdded       *time.Time `json:"kev_date_added,omitempty"`
	EPSSScore          float32    `json:"epss_score"`
	EPSSPercentile     float32    `json:"epss_percentile"`
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
	// KEVOnly restricts results to advisories with a CISA KEV entry —
	// "actually exploited in the wild." Implemented as an EXISTS
	// subquery against cisa_kev_entries on the canonical id, so the
	// count + items queries stay consistent.
	KEVOnly bool
	// EPSSMin filters to advisories whose EPSS score is at least this
	// value. Same EXISTS-on-canonical-id pattern as KEV; 0 disables
	// the filter (and matches "no EPSS row found" via the EXISTS
	// short-circuit, which is what we want — non-CVE ids stay visible
	// when no threshold is requested).
	EPSSMin float64
	Years   []string
	RepoID  string

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

// summaryVersion is the cache-invalidation watermark for every vuln
// dashboard read (summary, repos, facets, list). It is the last-refresh
// timestamp of the unified/canonical vuln MV family — see
// db.VulnViewsRefreshedAt for why this, and not the source-table
// watermarks, is the correct key: the cached responses are a pure function
// of those MVs, so they must invalidate exactly when the MVs rebuild and
// not on every source-table write.
//
// The previous shape captured four separate scan/OSV/VEX/image-scan
// maxes. Once the MV refresh interval was decoupled from ingestion (raised
// to hourly), those source watermarks advanced every few seconds while the
// MV data stayed identical, so the caches were perpetually "stale" and
// every read recomputed against the DB. Keying on the MV refresh time
// restores effective caching.
type summaryVersion struct {
	VulnViewsRefreshedAt *time.Time `json:"vuln_views_refreshed_at"`
}

type cachedSummary struct {
	Version summaryVersion `json:"version"`
	Summary Summary        `json:"summary"`
}

type cachedRepos struct {
	Version summaryVersion `json:"version"`
	Rows    []RepoRow      `json:"rows"`
}

// LoadSummary returns the cached summary if its version matches, the
// stale cached entry if it doesn't (kicking a background refresh), or
// computes synchronously if there's nothing cached at all.
//
// Stale-while-revalidate: the old version ran Refresh() inline whenever
// the version drifted, which is the path that timed out /api/vuln/summary
// — Refresh re-runs the unified-vuln MV refresh + computeSummary +
// computeRepos serialised inside the request. Mirrors the pattern in
// secrets_dashboard.go (table/trend/stats).
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
		// Stale: serve immediately, refresh in the background. The
		// existing refreshGate inside TriggerRefresh coalesces this
		// with any concurrent scan-completion triggers, so spammed
		// reads don't pile up redundant refreshes.
		TriggerRefresh(db)
		return entry.Summary, nil
	}

	// Cache miss (first request after deploy, or cache evicted) —
	// compute inline. After this returns, subsequent requests within
	// the same version see a cache hit.
	summary, _, err := Refresh(ctx, db, time.Now().UTC())
	return summary, err
}

// refreshGate coalesces concurrent TriggerRefresh calls. A single worker
// goroutine runs Refresh serially; additional triggers while a refresh
// is in flight flip `pending`, which schedules exactly one follow-up
// refresh after the current one — enough to capture the newest change
// without spawning N concurrent compute passes when scans batch-
// complete (common under the reconciler).
var refreshGate struct {
	mu       sync.Mutex
	inflight bool
	pending  bool
}

// unifiedViewsReadyCache flips to true the first time both unified vuln
// MVs are observed populated and stays true. The MVs only ever go back
// to unpopulated if a migration drops + recreates them WITH NO DATA;
// when that happens the process restarts (CREATE MATERIALIZED VIEW runs
// at boot) so the in-memory flag is reset by the restart anyway.
var unifiedViewsReadyCache atomic.Bool

// unifiedViewsReady returns true when both unified vuln MVs are
// populated and queries against them will succeed. Until the first
// async populate finishes (typically the first scan after deploy) this
// returns false and callers should short-circuit to an empty result —
// otherwise the bare SELECT raises SQLSTATE 55000 ("materialized view
// has not been populated").
func unifiedViewsReady(ctx context.Context, db *gorm.DB) bool {
	if unifiedViewsReadyCache.Load() {
		return true
	}
	ok, err := spamdb.VulnUnifiedViewsPopulated(ctx, db)
	if err != nil || !ok {
		return false
	}
	unifiedViewsReadyCache.Store(true)
	return true
}

// EnsureFirstPopulate blocks until both unified vuln MVs are populated.
// Spawn from a startup goroutine so HTTP serving isn't gated on it.
//
// Multi-replica safe: RefreshVulnUnifiedViews holds an advisory lock so
// only one replica actually performs the REFRESH; others observe
// ErrRefreshLockHeld and poll. We back off between iterations so a
// transient failure (e.g. underlying scan tables still seeding) gets
// retried instead of leaving the views unpopulated forever.
//
// Returns when ctx is cancelled or the views are populated.
func EnsureFirstPopulate(ctx context.Context, db *gorm.DB) error {
	backoff := 2 * time.Second
	for {
		if unifiedViewsReady(ctx, db) {
			return nil
		}
		if _, err := spamdb.RefreshVulnUnifiedViews(ctx, db); err != nil && err != spamdb.ErrRefreshLockHeld {
			log.Printf("vulnmetrics: first populate refresh: %v", err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff):
		}
		if backoff < 30*time.Second {
			backoff *= 2
		}
	}
}

// TriggerRefresh proactively warms the summary / repos caches in the
// background. Call from any scan-completion hook (SBOM, OSV batch,
// image scan finish, VEX edit) so the next user hits a warm cache
// instead of paying the recompute cost on their page load. Safe to
// call from multiple goroutines and rapid sequences — see refreshGate.
func TriggerRefresh(db *gorm.DB) {
	refreshGate.mu.Lock()
	if refreshGate.inflight {
		refreshGate.pending = true
		refreshGate.mu.Unlock()
		return
	}
	refreshGate.inflight = true
	refreshGate.mu.Unlock()

	go func() {
		for {
			// context.Background so a cancelled scanner/HTTP request
			// doesn't abort the refresh mid-flight; timeout bounds
			// us against a hung DB query.
			ctx, cancel := context.WithTimeout(context.Background(), refreshMaxRuntime)
			if _, viewsRefreshed, err := Refresh(ctx, db, time.Now().UTC()); err != nil {
				log.Printf("vulnmetrics: background refresh: %v", err)
				// Skipping the assetrisk cascade is deliberate — asset_risk
				// reads from the vuln_unified MVs, so refreshing it against
				// data we just failed to recompute would record a stale
				// snapshot. The log line makes the staleness visible to ops
				// instead of silently letting asset_risk drift.
				log.Printf("vulnmetrics: skipping assetrisk cascade (vulnmetrics refresh failed)")
			} else if viewsRefreshed {
				// asset_risk reads the unified vulnerability MVs. Cascade
				// after the vuln refresh has had a chance to land instead
				// of letting scan hooks trigger both families in parallel
				// against mismatched snapshots. Gated on an actual REFRESH:
				// a debounce-skipped pass left the MVs byte-identical, so
				// rebuilding asset_risk from them would be a no-op — the
				// unconditional cascade is what kept asset_risk rebuilding
				// at its debounce floor around the clock.
				assetrisk.TriggerRefresh(db)
			}
			cancel()

			refreshGate.mu.Lock()
			if !refreshGate.pending {
				refreshGate.inflight = false
				refreshGate.mu.Unlock()
				return
			}
			refreshGate.pending = false
			refreshGate.mu.Unlock()
			// Loop to absorb the trigger that arrived mid-refresh.
		}
	}()
}

// Refresh rebuilds the unified vuln MVs (debounced) and recomputes the
// summary/repos caches. The bool reports whether the MV refresh
// actually executed — false means the debounce window or another
// replica's in-flight refresh short-circuited it. TriggerRefresh uses
// it to cascade asset_risk only when the views it reads changed.
func Refresh(ctx context.Context, db *gorm.DB, capturedAt time.Time) (Summary, bool, error) {
	// Refresh the unified vuln MVs first so computeSummary / computeRepos
	// observe the freshest scan data. ErrRefreshLockHeld means another
	// replica is already refreshing — its result will land before ours
	// would have, so treat it as a no-op rather than an error. Other
	// failures fall through; computeSummary will then either see stale
	// data (acceptable) or, on first start, return zero-value rows
	// (handled by the unpopulated guard in LoadSummary / LoadListPage).
	viewsRefreshed, err := spamdb.RefreshVulnUnifiedViews(ctx, db)
	if err != nil && err != spamdb.ErrRefreshLockHeld {
		log.Printf("vulnmetrics: refresh unified views: %v", err)
	}

	summary, err := computeSummary(ctx, db)
	if err != nil {
		return Summary{}, viewsRefreshed, err
	}
	repos, err := computeRepos(ctx, db)
	if err != nil {
		return Summary{}, viewsRefreshed, err
	}
	version, err := querySummaryVersion(ctx, db)
	if err != nil {
		return Summary{}, viewsRefreshed, err
	}

	store := cache.NewPostgresStore(db)
	if err := cache.SetJSON(ctx, store, summaryCacheKey, cachedSummary{
		Version: version,
		Summary: summary,
	}, summaryCacheTTL); err != nil {
		return Summary{}, viewsRefreshed, err
	}
	if err := cache.SetJSON(ctx, store, reposCacheKey, cachedRepos{
		Version: version,
		Rows:    repos,
	}, summaryCacheTTL); err != nil {
		return Summary{}, viewsRefreshed, err
	}

	if err := upsertSnapshot(ctx, db, capturedAt.UTC(), summary); err != nil {
		return Summary{}, viewsRefreshed, err
	}

	return summary, viewsRefreshed, nil
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

// LoadTrendScoped is the narrow-grant counterpart to LoadTrend. The
// daily snapshot table is fleet-global with no per-asset breakdown,
// so for callers with narrower visibility we recompute the series.
//
// Semantics: for each day in the window, count the caller's open
// canonical vulns whose activation date is on or before that day. The
// curve grows monotonically toward today, where today's value equals
// the scoped summary card's open count (every canonical with a scan
// date <= today is counted). The cumulative form replaces an earlier
// scan-day binning that left "today = 0" whenever no scan happened to
// finish on the current day — the chart looked broken next to a summary
// card showing thousands of open findings.
//
// repoSQL / imageSQL are the same ACL predicates LoadSummaryScoped and
// VulnListHandler pass — predicates against the `v` alias on the unified
// views. Empty or "FALSE" excludes that branch.
//
// Cached per (subject ACL fragments, days) against the MV-refresh
// watermark, so a rebuild invalidates exactly when the underlying MVs
// change — same scheme as the list cache.
func LoadTrendScoped(ctx context.Context, db *gorm.DB, days int, repoSQL string, repoArgs []any, imageSQL string, imageArgs []any) ([]TrendPoint, error) {
	if days <= 0 {
		days = 30
	}
	if !unifiedViewsReady(ctx, db) {
		return []TrendPoint{}, nil
	}

	store := cache.NewPostgresStore(db)
	version, versionErr := querySummaryVersion(ctx, db)
	var cacheKey string
	if versionErr == nil {
		cacheKey = trendScopedCacheKey(version, days, repoSQL, repoArgs, imageSQL, imageArgs)
		if entry, ok, err := cache.GetJSON[cachedTrend](ctx, store, cacheKey); err == nil && ok {
			if sameVersion(entry.Version, version) {
				return entry.Rows, nil
			}
		}
	}

	rsql := strings.TrimSpace(repoSQL)
	if rsql == "" {
		rsql = "FALSE"
	}
	isql := strings.TrimSpace(imageSQL)
	if isql == "" {
		isql = "FALSE"
	}

	var rows []TrendPoint
	var err error
	if canonicalReady, _ := spamdb.VulnCanonicalViewsPopulated(ctx, db); canonicalReady {
		rows, err = trendScopedFromCanonical(ctx, db, days, rsql, repoArgs, isql, imageArgs)
	} else {
		rows, err = trendScopedFromUnified(ctx, db, days, rsql, repoArgs, isql, imageArgs)
	}
	if err != nil {
		return nil, err
	}
	if rows == nil {
		rows = []TrendPoint{}
	}

	if versionErr == nil && cacheKey != "" {
		_ = cache.SetJSON(ctx, store, cacheKey, cachedTrend{Version: version, Rows: rows}, summaryCacheTTL)
	}
	return rows, nil
}

// trendScopedFromCanonical builds the cumulative series from the
// pre-aggregated vuln_canonical_assets MV. Canonicalization and sev_rank
// are baked in, so this collapses straight to per-canonical and skips
// the request-time UNION + vuln_metadata join the bootstrap fallback
// does. The activation day is the canonical's earliest per-asset
// last_scanned_at — the MV carries last_scanned_at, not the first scan,
// so the historical ramp leans slightly toward recent days versus the
// fallback. The endpoint is unaffected: every canonical with a scan date
// counts at today, so the curve still terminates at the scoped summary
// card's open count.
func trendScopedFromCanonical(ctx context.Context, db *gorm.DB, days int, repoSQL string, repoArgs []any, imageSQL string, imageArgs []any) ([]TrendPoint, error) {
	// ACL pushed into the per-asset_type UNION-ALL CTE so each branch can
	// use its partial index instead of seq-scanning the MV. Bind order
	// follows the WITH clauses: dates (days) then scoped_assets (ACL).
	cte, aclArgs := scopedAssetsCTE(repoSQL, repoArgs, imageSQL, imageArgs)
	query := `
		WITH dates AS (
			SELECT (CURRENT_DATE - g)::date AS d
			FROM generate_series(0, ?::int - 1) AS g
		),
		scoped_assets AS (` + cte + `),
		per_canonical AS (
			SELECT canonical_id,
			       MIN(sev_rank) AS sev_rank,
			       MIN(last_scanned_at::date) AS first_day
			FROM scoped_assets vca
			WHERE last_scanned_at IS NOT NULL
			GROUP BY canonical_id
		)
		SELECT
			TO_CHAR(d.d, 'YYYY-MM-DD') AS date,
			COALESCE(SUM(CASE WHEN pc.sev_rank = 1 AND pc.first_day <= d.d THEN 1 ELSE 0 END), 0)::int AS critical,
			COALESCE(SUM(CASE WHEN pc.sev_rank = 2 AND pc.first_day <= d.d THEN 1 ELSE 0 END), 0)::int AS high,
			COALESCE(SUM(CASE WHEN pc.sev_rank = 3 AND pc.first_day <= d.d THEN 1 ELSE 0 END), 0)::int AS medium,
			COALESCE(SUM(CASE WHEN pc.sev_rank = 4 AND pc.first_day <= d.d THEN 1 ELSE 0 END), 0)::int AS low,
			COALESCE(SUM(CASE WHEN pc.sev_rank = 5 AND pc.first_day <= d.d THEN 1 ELSE 0 END), 0)::int AS unknown
		FROM dates d
		LEFT JOIN per_canonical pc ON TRUE
		GROUP BY d.d
		ORDER BY d.d ASC
	`

	args := []any{days}
	args = append(args, aclArgs...)

	var rows []TrendPoint
	if err := db.WithContext(ctx).Raw(query, args...).Scan(&rows).Error; err != nil {
		return nil, err
	}
	return rows, nil
}

// trendScopedFromUnified is the bootstrap fallback used before the
// canonical MVs populate. It re-aggregates from the per-finding unified
// views at request time: scoped → canonical_per_asset collapses
// (asset, vuln) findings onto canonical_id + worst severity, per_canonical
// dedupes across assets, and the activation day is the earliest observed
// scan date.
func trendScopedFromUnified(ctx context.Context, db *gorm.DB, days int, repoSQL string, repoArgs []any, imageSQL string, imageArgs []any) ([]TrendPoint, error) {
	query := fmt.Sprintf(`
		WITH dates AS (
			SELECT (CURRENT_DATE - g)::date AS d
			FROM generate_series(0, ?::int - 1) AS g
		),
		scoped AS (
			SELECT 'repo'::text AS asset_type, v.repo_id AS asset_id, v.vuln_id, v.severity, v.scanned_at::date AS day
			FROM view_unified_repositories_vulnerabilities v
			WHERE %s AND v.scanned_at IS NOT NULL
			UNION ALL
			SELECT 'image'::text AS asset_type, v.image_id AS asset_id, v.vuln_id, v.severity, v.scanned_at::date AS day
			FROM view_unified_image_vulnerabilities v
			WHERE %s AND v.scanned_at IS NOT NULL
		),
		canonical_per_asset AS (
			SELECT s.asset_type, s.asset_id,
			       COALESCE(vm.canonical_id, s.vuln_id) AS canonical_id,
			       MIN(CASE s.severity
			           WHEN 'CRITICAL' THEN 1
			           WHEN 'HIGH'     THEN 2
			           WHEN 'MEDIUM'   THEN 3
			           WHEN 'LOW'      THEN 4
			           ELSE 5
			       END) AS sev_rank,
			       MIN(s.day) AS first_day
			FROM scoped s
			LEFT JOIN vuln_metadata vm ON vm.vuln_id = s.vuln_id
			GROUP BY s.asset_type, s.asset_id, COALESCE(vm.canonical_id, s.vuln_id)
		),
		per_canonical AS (
			SELECT canonical_id,
			       MIN(sev_rank) AS sev_rank,
			       MIN(first_day) AS first_day
			FROM canonical_per_asset
			GROUP BY canonical_id
		)
		SELECT
			TO_CHAR(d.d, 'YYYY-MM-DD') AS date,
			COALESCE(SUM(CASE WHEN pc.sev_rank = 1 AND pc.first_day <= d.d THEN 1 ELSE 0 END), 0)::int AS critical,
			COALESCE(SUM(CASE WHEN pc.sev_rank = 2 AND pc.first_day <= d.d THEN 1 ELSE 0 END), 0)::int AS high,
			COALESCE(SUM(CASE WHEN pc.sev_rank = 3 AND pc.first_day <= d.d THEN 1 ELSE 0 END), 0)::int AS medium,
			COALESCE(SUM(CASE WHEN pc.sev_rank = 4 AND pc.first_day <= d.d THEN 1 ELSE 0 END), 0)::int AS low,
			COALESCE(SUM(CASE WHEN pc.sev_rank = 5 AND pc.first_day <= d.d THEN 1 ELSE 0 END), 0)::int AS unknown
		FROM dates d
		LEFT JOIN per_canonical pc ON TRUE
		GROUP BY d.d
		ORDER BY d.d ASC
	`, repoSQL, imageSQL)

	args := []any{days}
	args = append(args, repoArgs...)
	args = append(args, imageArgs...)

	var rows []TrendPoint
	if err := db.WithContext(ctx).Raw(query, args...).Scan(&rows).Error; err != nil {
		return nil, err
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

// Facets is the set of filter options the UI can show without risking
// zero-result selections — every value listed has at least one matching
// row somewhere in either the repo-side or image-side unified vuln view.
type Facets struct {
	Sources []string `json:"sources"`
	Years   []string `json:"years"`
}

type cachedFacets struct {
	Version summaryVersion `json:"version"`
	Facets  Facets         `json:"facets"`
}

// LoadFacets returns the distinct sources + CVE years currently present
// in the unified vuln views. Versioned against the same summaryVersion
// (the vuln MV refresh watermark) as LoadSummary so the cache drops the
// moment a rebuild could have introduced new values.
func LoadFacets(ctx context.Context, db *gorm.DB) (Facets, error) {
	store := cache.NewPostgresStore(db)

	version, err := querySummaryVersion(ctx, db)
	if err != nil {
		return Facets{}, err
	}

	if entry, ok, err := cache.GetJSON[cachedFacets](ctx, store, facetsCacheKey); err == nil && ok {
		if sameVersion(entry.Version, version) {
			return entry.Facets, nil
		}
	}

	facets, err := computeFacets(ctx, db)
	if err != nil {
		return Facets{}, err
	}

	if err := cache.SetJSON(ctx, store, facetsCacheKey, cachedFacets{
		Version: version,
		Facets:  facets,
	}, summaryCacheTTL); err != nil {
		return Facets{}, err
	}
	return facets, nil
}

func computeFacets(ctx context.Context, db *gorm.DB) (Facets, error) {
	out := Facets{Sources: []string{}, Years: []string{}}

	if !unifiedViewsReady(ctx, db) {
		return out, nil
	}

	if err := db.WithContext(ctx).Raw(`
		SELECT DISTINCT source
		FROM (
			SELECT source FROM view_unified_repositories_vulnerabilities
			UNION ALL
			SELECT source FROM view_unified_image_vulnerabilities
		) u
		WHERE source IS NOT NULL AND source <> ''
		ORDER BY source
	`).Scan(&out.Sources).Error; err != nil {
		return Facets{}, err
	}

	if err := db.WithContext(ctx).Raw(`
		SELECT DISTINCT substring(vuln_id FROM 'CVE-(\d{4})-') AS year
		FROM (
			SELECT vuln_id FROM view_unified_repositories_vulnerabilities
			UNION ALL
			SELECT vuln_id FROM view_unified_image_vulnerabilities
		) u
		WHERE vuln_id ~ '^CVE-\d{4}-'
		ORDER BY year DESC
	`).Scan(&out.Years).Error; err != nil {
		return Facets{}, err
	}
	return out, nil
}

type cachedListEntry struct {
	Version  summaryVersion   `json:"version"`
	Response VulnListResponse `json:"response"`
}

// listCacheKey hashes every input that affects the list response —
// filters, pagination, and the caller's ACL fragments (which implicitly
// scope results per-user). Collision on an 8-byte fnv-64a is harmless:
// a cache hit with mismatched params still runs the sameVersion check
// and, if versions match, we'd return someone else's page shaped
// identically to this request — which by construction produces the
// same rows (ACL args are part of the hash input).
func listCacheKey(version summaryVersion, p VulnListParams) string {
	h := fnv.New64a()
	enc := json.NewEncoder(h)
	_ = enc.Encode(version)
	_ = enc.Encode(struct {
		Limit, Offset              int
		Severities, Sources, Years []string
		Query                      string
		FixOnly                    bool
		KEVOnly                    bool
		EPSSMin                    float64
		RepoID                     string
		RepoSQL, ImageSQL          string
		RepoArgs, ImageArgs        []any
	}{
		p.Limit, p.Offset, p.Severities, p.Sources, p.Years,
		p.Query, p.FixOnly, p.KEVOnly, p.EPSSMin, p.RepoID, p.RepoSQL, p.ImageSQL,
		p.RepoArgs, p.ImageArgs,
	})
	return fmt.Sprintf("%s%x", listCachePrefix, h.Sum64())
}

// cachedTrend is the scoped-trend cache payload. Reuses summaryVersion
// (the MV-refresh watermark) so a rebuild orphans the entry.
type cachedTrend struct {
	Version summaryVersion `json:"version"`
	Rows    []TrendPoint   `json:"rows"`
}

// summaryScopedCacheKey / trendScopedCacheKey hash the caller's ACL
// fragments (+ days for trend) alongside the version, mirroring
// listCacheKey: identical readable sets collide onto one entry, which is
// correct because the result is a pure function of those fragments and
// the MV contents at that version.
func summaryScopedCacheKey(version summaryVersion, repoSQL string, repoArgs []any, imageSQL string, imageArgs []any) string {
	h := fnv.New64a()
	enc := json.NewEncoder(h)
	_ = enc.Encode(version)
	_ = enc.Encode(struct {
		RepoSQL, ImageSQL   string
		RepoArgs, ImageArgs []any
	}{repoSQL, imageSQL, repoArgs, imageArgs})
	return fmt.Sprintf("%s%x", summaryScopedCachePrefix, h.Sum64())
}

func trendScopedCacheKey(version summaryVersion, days int, repoSQL string, repoArgs []any, imageSQL string, imageArgs []any) string {
	h := fnv.New64a()
	enc := json.NewEncoder(h)
	_ = enc.Encode(version)
	_ = enc.Encode(struct {
		Days                int
		RepoSQL, ImageSQL   string
		RepoArgs, ImageArgs []any
	}{days, repoSQL, imageSQL, repoArgs, imageArgs})
	return fmt.Sprintf("%s%x", trendScopedCachePrefix, h.Sum64())
}

// LoadListPage returns a paginated page of grouped vulnerabilities,
// plus the total group count for the same filters. Cached per
// (version, filters, ACL scope, page); invalidated implicitly via
// summaryVersion — a vuln MV rebuild bumps the refresh watermark and
// changes the version hash, so stale keys are orphaned and expire via
// TTL. Fresh after every rebuild without a manual bust. (Source-table
// writes between rebuilds intentionally do NOT invalidate: the page is
// read from the MVs, whose contents don't change until they refresh.)
func LoadListPage(ctx context.Context, db *gorm.DB, p VulnListParams) (VulnListResponse, error) {
	// 50 is the default; 100 caps the page so a single request can't
	// pull the whole table. Old code defaulted to 100 and capped at
	// 500 — at scale that's a ~10x payload + planner cost for marginal
	// scrolling benefit. The list page virtualises so smaller pages
	// don't affect UX.
	if p.Limit <= 0 {
		p.Limit = 50
	}
	if p.Limit > 100 {
		p.Limit = 100
	}
	if p.Offset < 0 {
		p.Offset = 0
	}

	store := cache.NewPostgresStore(db)
	version, versionErr := querySummaryVersion(ctx, db)
	var cacheKey string
	if versionErr == nil {
		cacheKey = listCacheKey(version, p)
		if entry, ok, err := cache.GetJSON[cachedListEntry](ctx, store, cacheKey); err == nil && ok {
			if sameVersion(entry.Version, version) {
				return entry.Response, nil
			}
		}
	}

	// Short-circuit when the unified vuln MVs are still empty. Querying
	// them in that state raises SQLSTATE 55000; the UI handles a 0-total
	// response gracefully (empty state) and a follow-up TriggerRefresh
	// will populate them shortly. Skipping the cache write here is
	// deliberate — we don't want to lock in "0 results" for the cache TTL.
	if !unifiedViewsReady(ctx, db) {
		return VulnListResponse{Total: 0, Limit: p.Limit, Offset: p.Offset, Items: []VulnGroup{}}, nil
	}

	// Canonical MV paths. Both read pre-aggregated, indexed MVs and skip
	// the request-time UNION + vuln_metadata join + scanner-variant
	// collapse that the bootstrap fallback below performs.
	//
	//   - Admin path (no per-repo narrowing, unrestricted fragments) reads
	//     the per-canonical vuln_canonical_summary MV directly.
	//   - Scoped path reads vuln_canonical_assets, whose (asset, canonical)
	//     grain lets the caller's ACL filter on the indexed asset columns
	//     before grouping to one row per canonical.
	canonicalReady, _ := spamdb.VulnCanonicalViewsPopulated(ctx, db)
	isAdminListing := p.RepoID == "" &&
		(strings.TrimSpace(p.RepoSQL) == "" || strings.TrimSpace(p.RepoSQL) == "TRUE") &&
		(strings.TrimSpace(p.ImageSQL) == "" || strings.TrimSpace(p.ImageSQL) == "TRUE")
	if canonicalReady {
		var resp VulnListResponse
		var err error
		if isAdminListing {
			resp, err = loadListPageFromSummary(ctx, db, p)
		} else {
			resp, err = loadListPageScoped(ctx, db, p)
		}
		if err != nil {
			return VulnListResponse{}, err
		}
		if versionErr == nil && cacheKey != "" {
			_ = cache.SetJSON(ctx, store, cacheKey, cachedListEntry{
				Version:  version,
				Response: resp,
			}, summaryCacheTTL)
		}
		return resp, nil
	}

	// Bootstrap fallback: the canonical MVs are not yet populated (fresh
	// deploy, before the first refresh), so re-aggregate from the
	// per-finding unified views at request time.
	base, args := buildAssetUnionSQL(p)

	// Row-level filters on the UNION result (apply before GROUP BY so
	// they reduce the set the aggregate sees). Both the count and the
	// ranked CTE LEFT JOIN vuln_metadata vm, which exposes its own
	// vuln_id/title/severity columns — bare references would be
	// ambiguous, so every column here is qualified with the av alias
	// applied in both query bodies below.
	var where []string
	var whereArgs []any
	if len(p.Severities) > 0 {
		where = append(where, "av.severity IN ?")
		whereArgs = append(whereArgs, p.Severities)
	}
	if len(p.Sources) > 0 {
		where = append(where, "av.source IN ?")
		whereArgs = append(whereArgs, p.Sources)
	}
	if p.FixOnly {
		where = append(where, "av.fixed_version <> ''")
	}
	if p.KEVOnly {
		// EXISTS keyed on the canonical id (or the raw scanner-reported
		// id when no enrichment row exists yet). KEV is CVE-only, so
		// non-CVE advisories without a CVE alias correctly drop out.
		// Pushed into the same WHERE the count + ranked CTEs share so
		// total and items stay in lockstep.
		where = append(where, "EXISTS (SELECT 1 FROM cisa_kev_entries kev WHERE kev.cve_id = COALESCE(vm.canonical_id, av.vuln_id))")
	}
	if p.EPSSMin > 0 {
		// Same canonical-id EXISTS pattern as KEV. EPSS is CVE-only;
		// non-CVE ids without an EPSS row drop out, which matches the
		// intent ("show me likely-to-be-exploited" implies an EPSS row
		// exists).
		where = append(where, "EXISTS (SELECT 1 FROM epss_entries epss WHERE epss.cve_id = COALESCE(vm.canonical_id, av.vuln_id) AND epss.score >= ?)")
		whereArgs = append(whereArgs, p.EPSSMin)
	}
	if q := strings.TrimSpace(p.Query); q != "" {
		needle := "%" + strings.ToLower(q) + "%"
		// Alias-aware search: a scan may have stored a row under
		// BIT-valkey-2025-49844 while the user searches for its
		// CVE alias. The EXISTS subquery against vuln_metadata
		// brings those rows back without requiring the caller to
		// know which prefix the scanner picked.
		where = append(where,
			`(LOWER(av.vuln_id) LIKE ? OR LOWER(av.title) LIKE ? OR LOWER(av.pkg_name) LIKE ? OR LOWER(av.asset_slug) LIKE ?
			   OR EXISTS (
			     SELECT 1 FROM vuln_metadata vm2
			     WHERE vm2.vuln_id = av.vuln_id
			       AND LOWER(vm2.aliases::text) LIKE ?
			   ))`)
		whereArgs = append(whereArgs, needle, needle, needle, needle, needle)
	}
	if len(p.Years) > 0 {
		// cve_year is a smallint column on the unified MVs derived from
		// the vuln_id's "<prefix>-YYYY-NNNN" pattern; using it lets the
		// year-filter index do the work instead of a leading-wildcard
		// ILIKE that would force a sequential scan. p.Years holds
		// stringified ints from the API; convert and skip non-numeric
		// values defensively.
		var nums []int
		for _, y := range p.Years {
			n, err := strconv.Atoi(strings.TrimSpace(y))
			if err != nil || n <= 0 {
				continue
			}
			nums = append(nums, n)
		}
		if len(nums) > 0 {
			where = append(where, "av.cve_year IN ?")
			whereArgs = append(whereArgs, nums)
		}
	}

	var whereClause string
	if len(where) > 0 {
		whereClause = "WHERE " + strings.Join(where, " AND ")
	}

	// Count + group queries both go through a canonicalised
	// asset_vulns row: LEFT JOIN vuln_metadata, and the display/
	// grouping id is COALESCE(vm.canonical_id, av.vuln_id). Rows
	// without an enrichment row fall through as their own id; rows
	// with one collapse CVE / GHSA / BIT variants of the same
	// advisory into a single group.

	// Total count = distinct canonical id after filters.
	var total int
	countSQL := fmt.Sprintf(`
		WITH asset_vulns AS (%s)
		SELECT COUNT(DISTINCT COALESCE(vm.canonical_id, av.vuln_id))::int
		FROM asset_vulns av
		LEFT JOIN vuln_metadata vm ON vm.vuln_id = av.vuln_id
		%s
	`, base, whereClause)
	countArgs := append([]any{}, args...)
	countArgs = append(countArgs, whereArgs...)
	if err := db.WithContext(ctx).Raw(countSQL, countArgs...).Scan(&total).Error; err != nil {
		return VulnListResponse{}, err
	}

	// Grouped page. Two CTEs:
	//   ranked  — attaches canonical_id + sev_rank per asset row.
	//   grouped — collapses to one row per canonical_id with the
	//             aggregates the response shape needs.
	// The outer SELECT then LEFT JOINs the bulk-fetched KEV / EPSS
	// feeds on canonical_id (CVE-prefixed, which both feeds use as
	// their key) so the ORDER BY can prefer "actually exploited" >
	// "high exploit probability" > "worst severity" > "most recent".
	// LEFT JOINs leave non-CVE ids (GHSA-*, BIT-*) unboosted, which
	// is correct: KEV / EPSS only score CVE identifiers.
	groupSQL := fmt.Sprintf(`
		WITH asset_vulns AS (%s),
		ranked AS (
			SELECT av.*,
				COALESCE(vm.canonical_id, av.vuln_id) AS canonical_id,
				CASE av.severity
					WHEN 'CRITICAL' THEN 1
					WHEN 'HIGH'     THEN 2
					WHEN 'MEDIUM'   THEN 3
					WHEN 'LOW'      THEN 4
					ELSE 5
				END AS sev_rank
			FROM asset_vulns av
			LEFT JOIN vuln_metadata vm ON vm.vuln_id = av.vuln_id
			%s
		),
		grouped AS (
			SELECT
				canonical_id AS vuln_id,
				MIN(sev_rank) AS sev_rank,
				-- Year extracted from the canonical id
				-- ("<prefix>-YYYY-NNNN") for the recency tiebreak.
				-- NULL when the prefix doesn't carry a year.
				substring(canonical_id from '-(\d{4})-')::int AS cve_year,
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
					'type', asset_type, 'id', asset_id, 'slug', asset_slug, 'digest', asset_digest
				)) AS assets,
				COUNT(DISTINCT CASE WHEN asset_type = 'repo'  THEN asset_id END)::int AS repo_count,
				COUNT(DISTINCT CASE WHEN asset_type = 'image' THEN asset_id END)::int AS image_count
			FROM ranked
			GROUP BY canonical_id
		)
		SELECT
			g.vuln_id, g.sev_rank, g.cve_year,
			g.severity, g.pkg_name, g.installed_version, g.fixed_version,
			g.title, g.description, g.sources, g.assets,
			g.repo_count, g.image_count,
			(kev.cve_id IS NOT NULL)            AS kev_known,
			COALESCE(kev.known_ransomware, FALSE) AS kev_known_ransomware,
			kev.date_added                       AS kev_date_added,
			COALESCE(epss.score, 0)::float       AS epss_score,
			COALESCE(epss.percentile, 0)::float  AS epss_percentile
		FROM grouped g
		LEFT JOIN cisa_kev_entries kev ON kev.cve_id = g.vuln_id
		LEFT JOIN epss_entries     epss ON epss.cve_id = g.vuln_id
		-- Severity first (Critical → Unknown), then KEV, then EPSS,
		-- then newer CVE year, then alphabetical id for stability.
		-- Severity-leading matches how operators read the list — a
		-- Critical without KEV still beats a High that is KEV-listed,
		-- because severity is the worst-case impact and KEV / EPSS
		-- are tiebreakers within the same impact tier.
		ORDER BY g.sev_rank                      ASC,
		         (kev.cve_id IS NOT NULL)        DESC,
		         COALESCE(epss.score, 0)         DESC,
		         g.cve_year                      DESC NULLS LAST,
		         g.vuln_id                       ASC
		LIMIT ? OFFSET ?
	`, base, whereClause)

	groupArgs := append([]any{}, args...)
	groupArgs = append(groupArgs, whereArgs...)
	groupArgs = append(groupArgs, p.Limit, p.Offset)

	var raws []listGroupRow
	if err := db.WithContext(ctx).Raw(groupSQL, groupArgs...).Scan(&raws).Error; err != nil {
		return VulnListResponse{}, err
	}

	resp := VulnListResponse{
		Total:  total,
		Limit:  p.Limit,
		Offset: p.Offset,
		Items:  finalizeListItems(ctx, db, raws),
	}

	if versionErr == nil && cacheKey != "" {
		_ = cache.SetJSON(ctx, store, cacheKey, cachedListEntry{
			Version:  version,
			Response: resp,
		}, summaryCacheTTL)
	}

	return resp, nil
}

// listGroupRow is the raw scan target shared by all three list query
// paths (admin summary MV, scoped canonical-assets, bootstrap union).
// Every path projects this exact column set so they can share
// finalizeListItems for the JSON decode + metadata enrichment pass.
type listGroupRow struct {
	VulnID             string          `gorm:"column:vuln_id"`
	SevRank            int             `gorm:"column:sev_rank"`
	CVEYear            *int            `gorm:"column:cve_year"`
	Severity           string          `gorm:"column:severity"`
	PkgName            string          `gorm:"column:pkg_name"`
	InstalledVersion   string          `gorm:"column:installed_version"`
	FixedVersion       string          `gorm:"column:fixed_version"`
	Title              string          `gorm:"column:title"`
	Description        string          `gorm:"column:description"`
	Sources            json.RawMessage `gorm:"column:sources"`
	Assets             json.RawMessage `gorm:"column:assets"`
	RepoCount          int             `gorm:"column:repo_count"`
	ImageCount         int             `gorm:"column:image_count"`
	KEVKnown           bool            `gorm:"column:kev_known"`
	KEVKnownRansomware bool            `gorm:"column:kev_known_ransomware"`
	KEVDateAdded       *time.Time      `gorm:"column:kev_date_added"`
	EPSSScore          float32         `gorm:"column:epss_score"`
	EPSSPercentile     float32         `gorm:"column:epss_percentile"`
}

// finalizeListItems decodes the aggregated JSON columns and runs the one
// bulk vuln_metadata pass (aliases + OSV applicable-fix override) every
// list query path shares. items[i].VulnID is the canonical id, so the
// MetadataForMany lookup matches on canonical_id OR vuln_id.
func finalizeListItems(ctx context.Context, db *gorm.DB, raws []listGroupRow) []VulnGroup {
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
			VulnID:             r.VulnID,
			Severity:           r.Severity,
			PkgName:            r.PkgName,
			InstalledVersion:   r.InstalledVersion,
			FixedVersion:       r.FixedVersion,
			Title:              r.Title,
			Description:        r.Description,
			Sources:            sources,
			Assets:             assets,
			RepoCount:          r.RepoCount,
			ImageCount:         r.ImageCount,
			KEVKnown:           r.KEVKnown,
			KEVKnownRansomware: r.KEVKnownRansomware,
			KEVDateAdded:       r.KEVDateAdded,
			EPSSScore:          r.EPSSScore,
			EPSSPercentile:     r.EPSSPercentile,
		})
	}

	if len(items) > 0 {
		ids := make([]string, 0, len(items))
		for _, it := range items {
			ids = append(ids, it.VulnID)
		}
		if metas, err := vulnmeta.MetadataForMany(ctx, db, ids); err == nil {
			for i := range items {
				meta := metas[items[i].VulnID]
				if meta == nil {
					continue
				}
				// Aliases: drop the canonical itself from the
				// cross-reference list shown beside it.
				aliases := vulnmeta.Aliases(meta)
				out := aliases[:0]
				for _, a := range aliases {
					if a != items[i].VulnID {
						out = append(out, a)
					}
				}
				if len(out) > 0 {
					items[i].Aliases = out
				}
				// Fix-version override: prefer OSV's own range data when
				// it resolves for this package / installed version.
				if fix := vulnmeta.ApplicableFix(
					vulnmeta.ExtractOSVAffected(meta),
					items[i].PkgName,
					items[i].InstalledVersion,
				); fix != "" {
					items[i].FixedVersion = fix
				}
			}
		}
	}
	return items
}

// loadListPageFromSummary is the admin fast-path. Reads directly from
// the per-canonical vuln_canonical_summary MV which has the GROUP BY
// already done, KEV / EPSS pre-joined, and a btree index matching the
// UI's ORDER BY tuple. Page reads become index-ordered LIMIT scans.
//
// Filters are applied against MV columns directly:
//   - severity        → severity IN ?
//   - sources         → sources ?| ?  (jsonb ?| accepts text[])
//   - fix_only        → has_fix
//   - kev_only        → kev_known
//   - epss_min        → epss_score >= ?
//   - years           → cve_year IN ?
//   - query           → LIKE on vuln_id/title/pkg_name + alias EXISTS;
//                        asset_slug match falls back to a canonical_assets
//                        EXISTS so admin search keeps the same surface as
//                        the legacy union-CTE path.
//
// Same response shape as the legacy path so the handler doesn't see a
// difference; same MetadataForMany aliases-and-osv-fix pass runs after.
func loadListPageFromSummary(ctx context.Context, db *gorm.DB, p VulnListParams) (VulnListResponse, error) {
	var where []string
	var whereArgs []any
	if len(p.Severities) > 0 {
		where = append(where, "severity IN ?")
		whereArgs = append(whereArgs, p.Severities)
	}
	if len(p.Sources) > 0 {
		// sources is jsonb_agg of distinct source names. ?| takes
		// text[]; gorm/pgx encodes []string as text[] when the column
		// type matches.
		where = append(where, "sources ?| ?")
		whereArgs = append(whereArgs, p.Sources)
	}
	if p.FixOnly {
		where = append(where, "has_fix")
	}
	if p.KEVOnly {
		where = append(where, "kev_known")
	}
	if p.EPSSMin > 0 {
		where = append(where, "epss_score >= ?")
		whereArgs = append(whereArgs, p.EPSSMin)
	}
	if len(p.Years) > 0 {
		var nums []int
		for _, y := range p.Years {
			n, err := strconv.Atoi(strings.TrimSpace(y))
			if err != nil || n <= 0 {
				continue
			}
			nums = append(nums, n)
		}
		if len(nums) > 0 {
			where = append(where, "cve_year IN ?")
			whereArgs = append(whereArgs, nums)
		}
	}
	if q := strings.TrimSpace(p.Query); q != "" {
		needle := "%" + strings.ToLower(q) + "%"
		where = append(where, `(
			LOWER(vuln_id)  LIKE ? OR LOWER(title) LIKE ? OR LOWER(pkg_name) LIKE ?
			OR EXISTS (
				SELECT 1 FROM vuln_metadata vm2
				WHERE vm2.vuln_id = vcs.vuln_id
				  AND LOWER(vm2.aliases::text) LIKE ?
			)
			OR EXISTS (
				SELECT 1 FROM vuln_canonical_assets vca
				WHERE vca.canonical_id = vcs.vuln_id
				  AND LOWER(vca.asset_slug) LIKE ?
			)
		)`)
		whereArgs = append(whereArgs, needle, needle, needle, needle, needle)
	}

	whereClause := ""
	if len(where) > 0 {
		whereClause = "WHERE " + strings.Join(where, " AND ")
	}

	// Total = matching canonical count. No DISTINCT needed; vuln_id is
	// the MV's unique key.
	var total int
	countSQL := "SELECT COUNT(*)::int FROM vuln_canonical_summary vcs " + whereClause
	if err := db.WithContext(ctx).Raw(countSQL, whereArgs...).Scan(&total).Error; err != nil {
		return VulnListResponse{}, err
	}

	// Page rows. ORDER BY matches the idx_vuln_canonical_summary_rank
	// btree precisely (per-column direction), so the planner picks
	// an index scan + LIMIT stopping early — no sort step.
	pageSQL := `
		SELECT
			vuln_id, sev_rank, cve_year,
			severity, pkg_name, installed_version, fixed_version,
			title, description, sources, assets,
			repo_count, image_count,
			kev_known, kev_known_ransomware, kev_date_added,
			epss_score, epss_percentile
		FROM vuln_canonical_summary vcs
		` + whereClause + `
		ORDER BY sev_rank                ASC,
		         kev_known               DESC,
		         epss_score              DESC,
		         cve_year                DESC NULLS LAST,
		         vuln_id                 ASC
		LIMIT ? OFFSET ?
	`
	pageArgs := append([]any{}, whereArgs...)
	pageArgs = append(pageArgs, p.Limit, p.Offset)

	var raws []listGroupRow
	if err := db.WithContext(ctx).Raw(pageSQL, pageArgs...).Scan(&raws).Error; err != nil {
		return VulnListResponse{}, err
	}

	return VulnListResponse{
		Total:  total,
		Limit:  p.Limit,
		Offset: p.Offset,
		Items:  finalizeListItems(ctx, db, raws),
	}, nil
}

// loadListPageScoped is the narrow-grant counterpart to
// loadListPageFromSummary. Admins read the per-canonical
// vuln_canonical_summary MV; scoped callers can't, because that MV is
// already collapsed across assets and ACL filters at asset grain. This
// reads vuln_canonical_assets instead — one row per (asset, canonical)
// with canonicalization, sev_rank, and display fields baked in at
// refresh time — applies the caller's ACL on the indexed
// (asset_type, asset_id) columns, then groups to one row per canonical.
// It replaces the old request-time UNION of the per-finding views +
// vuln_metadata join + scanner-variant collapse (buildAssetUnionSQL)
// that scoped users used to pay on every page load.
func loadListPageScoped(ctx context.Context, db *gorm.DB, p VulnListParams) (VulnListResponse, error) {
	repoSQL := strings.TrimSpace(p.RepoSQL)
	if repoSQL == "" {
		repoSQL = "FALSE"
	}
	imageSQL := strings.TrimSpace(p.ImageSQL)
	if imageSQL == "" {
		imageSQL = "FALSE"
	}
	repoArgs := append([]any{}, p.RepoArgs...)
	imageArgs := append([]any{}, p.ImageArgs...)
	// Repo-detail drill-down: narrow the repo branch to the one repo and
	// drop the image branch entirely, matching buildAssetUnionSQL. The
	// v.repo_id reference is rewritten to asset_id by scopedAssetsCTE.
	if p.RepoID != "" {
		repoSQL = fmt.Sprintf("(%s) AND v.repo_id = ?", repoSQL)
		repoArgs = append(repoArgs, p.RepoID)
		imageSQL = "FALSE"
		imageArgs = nil
	}

	// ACL lives inside the UNION-ALL CTE so each asset_type branch can use
	// its partial index; the remaining filters apply to the unioned set.
	cte, aclArgs := scopedAssetsCTE(repoSQL, repoArgs, imageSQL, imageArgs)

	var filt []string
	var filtArgs []any
	if len(p.Severities) > 0 {
		filt = append(filt, "vca.severity IN ?")
		filtArgs = append(filtArgs, p.Severities)
	}
	if len(p.Sources) > 0 {
		// sources is the per-asset jsonb source list; ?| matches any.
		filt = append(filt, "vca.sources ?| ?")
		filtArgs = append(filtArgs, p.Sources)
	}
	if p.FixOnly {
		filt = append(filt, "vca.has_fix")
	}
	if p.KEVOnly {
		filt = append(filt, "EXISTS (SELECT 1 FROM cisa_kev_entries kev WHERE kev.cve_id = vca.canonical_id)")
	}
	if p.EPSSMin > 0 {
		filt = append(filt, "EXISTS (SELECT 1 FROM epss_entries epss WHERE epss.cve_id = vca.canonical_id AND epss.score >= ?)")
		filtArgs = append(filtArgs, p.EPSSMin)
	}
	if len(p.Years) > 0 {
		var nums []int
		for _, y := range p.Years {
			n, err := strconv.Atoi(strings.TrimSpace(y))
			if err != nil || n <= 0 {
				continue
			}
			nums = append(nums, n)
		}
		if len(nums) > 0 {
			filt = append(filt, "vca.cve_year IN ?")
			filtArgs = append(filtArgs, nums)
		}
	}
	if q := strings.TrimSpace(p.Query); q != "" {
		needle := "%" + strings.ToLower(q) + "%"
		// asset_slug is a row-level column here, so unlike the admin path
		// it needs no canonical_assets EXISTS subquery. Alias search keys
		// on the canonical id, mirroring loadListPageFromSummary.
		filt = append(filt, `(
			LOWER(vca.canonical_id) LIKE ? OR LOWER(vca.title) LIKE ? OR LOWER(vca.pkg_name) LIKE ? OR LOWER(vca.asset_slug) LIKE ?
			OR EXISTS (
				SELECT 1 FROM vuln_metadata vm2
				WHERE vm2.vuln_id = vca.canonical_id
				  AND LOWER(vm2.aliases::text) LIKE ?
			)
		)`)
		filtArgs = append(filtArgs, needle, needle, needle, needle, needle)
	}

	filterClause := ""
	if len(filt) > 0 {
		filterClause = "WHERE " + strings.Join(filt, " AND ")
	}

	// Total = distinct canonical ids the caller can see after filters.
	// ACL args (CTE) precede the filter args in bind order.
	var total int
	countSQL := "WITH scoped_assets AS (" + cte + ") SELECT COUNT(DISTINCT canonical_id)::int FROM scoped_assets vca " + filterClause
	countArgs := append([]any{}, aclArgs...)
	countArgs = append(countArgs, filtArgs...)
	if err := db.WithContext(ctx).Raw(countSQL, countArgs...).Scan(&total).Error; err != nil {
		return VulnListResponse{}, err
	}

	// Group the (asset, canonical) rows to one per canonical, picking
	// display fields from the worst-severity asset (mirrors the legacy
	// `grouped` CTE) and merging the per-asset source lists. KEV / EPSS
	// feeds join on the canonical id for the exploit-weighted ORDER BY.
	pageSQL := `
		WITH scoped_assets AS (` + cte + `),
		grouped AS (
			SELECT
				canonical_id AS vuln_id,
				MIN(sev_rank) AS sev_rank,
				MAX(cve_year)::int AS cve_year,
				(ARRAY_AGG(severity          ORDER BY sev_rank ASC, asset_id ASC))[1] AS severity,
				(ARRAY_AGG(pkg_name          ORDER BY sev_rank ASC, asset_id ASC))[1] AS pkg_name,
				(ARRAY_AGG(installed_version ORDER BY sev_rank ASC, asset_id ASC))[1] AS installed_version,
				(ARRAY_AGG(fixed_version     ORDER BY sev_rank ASC, asset_id ASC))[1] AS fixed_version,
				(ARRAY_AGG(title             ORDER BY sev_rank ASC, asset_id ASC))[1] AS title,
				(ARRAY_AGG(description       ORDER BY sev_rank ASC, asset_id ASC))[1] AS description,
				-- Merge the per-asset jsonb source lists into one distinct
				-- set: array_agg gathers the group's jsonb arrays, unnest
				-- yields each array, jsonb_array_elements_text flattens.
				COALESCE(
					(SELECT jsonb_agg(DISTINCT s)
					 FROM unnest(array_agg(vca.sources)) AS arr,
					      jsonb_array_elements_text(arr) AS s
					 WHERE s IS NOT NULL AND s <> ''),
					'[]'::jsonb
				) AS sources,
				jsonb_agg(DISTINCT jsonb_build_object(
					'type', asset_type, 'id', asset_id, 'slug', asset_slug, 'digest', asset_digest
				)) AS assets,
				COUNT(DISTINCT CASE WHEN asset_type = 'repo'  THEN asset_id END)::int AS repo_count,
				COUNT(DISTINCT CASE WHEN asset_type = 'image' THEN asset_id END)::int AS image_count
			FROM scoped_assets vca
			` + filterClause + `
			GROUP BY canonical_id
		)
		SELECT
			g.vuln_id, g.sev_rank, g.cve_year,
			g.severity, g.pkg_name, g.installed_version, g.fixed_version,
			g.title, g.description, g.sources, g.assets,
			g.repo_count, g.image_count,
			(kev.cve_id IS NOT NULL)              AS kev_known,
			COALESCE(kev.known_ransomware, FALSE) AS kev_known_ransomware,
			kev.date_added                        AS kev_date_added,
			COALESCE(epss.score, 0)::float        AS epss_score,
			COALESCE(epss.percentile, 0)::float   AS epss_percentile
		FROM grouped g
		LEFT JOIN cisa_kev_entries kev ON kev.cve_id = g.vuln_id
		LEFT JOIN epss_entries     epss ON epss.cve_id = g.vuln_id
		ORDER BY g.sev_rank                      ASC,
		         (kev.cve_id IS NOT NULL)        DESC,
		         COALESCE(epss.score, 0)         DESC,
		         g.cve_year                      DESC NULLS LAST,
		         g.vuln_id                       ASC
		LIMIT ? OFFSET ?
	`
	pageArgs := append([]any{}, aclArgs...)
	pageArgs = append(pageArgs, filtArgs...)
	pageArgs = append(pageArgs, p.Limit, p.Offset)

	var raws []listGroupRow
	if err := db.WithContext(ctx).Raw(pageSQL, pageArgs...).Scan(&raws).Error; err != nil {
		return VulnListResponse{}, err
	}

	return VulnListResponse{
		Total:  total,
		Limit:  p.Limit,
		Offset: p.Offset,
		Items:  finalizeListItems(ctx, db, raws),
	}, nil
}

// canonicalAssetWhere rewrites the unified-view-shaped ACL fragments
// (alias `v` with columns `v.repo_id` / `v.image_id`) into a single
// predicate against vuln_canonical_assets columns (asset_type +
// asset_id). The substitution relies on a convention enforced by the
// uiapi.repoSubquery / imageSubquery helpers:
//
//   - "TRUE"  / "FALSE" → preserved as-is.
//   - "v.repo_id  IN (...)" / "v.image_id IN (...)" → only `v.repo_id`
//     and `v.image_id` reference the unified-view alias; inner clause
//     SQL uses other aliases ("r", "d"), so a literal substring
//     replace doesn't bleed into those subqueries.
//
// The returned fragment is `((asset_type='repo'  AND repoSQL') OR
// (asset_type='image' AND imageSQL'))` — the asset_type guard makes
// "TRUE" branches scope to their own asset family without enabling
// the other, matching the existing per-branch UNION semantics.
//
// IMPORTANT: if you add new ACL helpers that produce fragments with
// other `v.<col>` references, update this function (or build a
// canonical-shaped fragment directly) before passing them in.
func canonicalAssetWhere(repoSQL, imageSQL string) string {
	rc := strings.ReplaceAll(repoSQL, "v.repo_id", "asset_id")
	ic := strings.ReplaceAll(imageSQL, "v.image_id", "asset_id")
	return fmt.Sprintf("((asset_type = 'repo' AND %s) OR (asset_type = 'image' AND %s))", rc, ic)
}

// scopedAssetsCTE builds a UNION ALL of the two asset-type branches over
// vuln_canonical_assets, each constrained to a single asset_type so the
// partial indexes (idx_vuln_canonical_assets_repo / _image, both on
// asset_id) can drive a semi-join against the caller's small readable-id
// set. The body is meant to seed a `WITH scoped_assets AS (...)` CTE that
// downstream queries group / filter over.
//
// Why not canonicalAssetWhere's single OR predicate: ORing the two
// asset_type branches into one WHERE forces Postgres to seq-scan the
// whole MV — neither partial index covers an asset_type-spanning OR — so
// the scoped dashboard paid a full-table scan per request even for a
// tiny grant. Splitting into per-asset_type branches restores index use.
//
// repoSQL / imageSQL are the unified-view-shaped ACL fragments (alias
// `v`, columns v.repo_id / v.image_id); the v.<col> references are
// rewritten to asset_id, same convention as canonicalAssetWhere. Args
// are returned in repo-branch-then-image-branch order.
func scopedAssetsCTE(repoSQL string, repoArgs []any, imageSQL string, imageArgs []any) (string, []any) {
	repoPred := "asset_type = 'repo' AND " + strings.ReplaceAll(repoSQL, "v.repo_id", "asset_id")
	imagePred := "asset_type = 'image' AND " + strings.ReplaceAll(imageSQL, "v.image_id", "asset_id")
	cte := fmt.Sprintf(`
		SELECT * FROM vuln_canonical_assets WHERE %s
		UNION ALL
		SELECT * FROM vuln_canonical_assets WHERE %s
	`, repoPred, imagePred)
	args := append([]any{}, repoArgs...)
	args = append(args, imageArgs...)
	return cte, args
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
			''::text                                    AS asset_digest,
			v.vuln_id, v.severity, v.pkg_name,
			v.installed_version, v.fixed_version,
			v.title, v.description, v.source, v.cve_year
		FROM view_unified_repositories_vulnerabilities v
		WHERE %s
		UNION ALL
		SELECT
			'image'::text                               AS asset_type,
			v.image_id                                  AS asset_id,
			v.image_slug                                AS asset_slug,
			COALESCE(d.digest, '')                      AS asset_digest,
			v.vuln_id, v.severity, v.pkg_name,
			v.installed_version, v.fixed_version,
			v.title, v.description, v.source, v.cve_year
		FROM view_unified_image_vulnerabilities v
		LEFT JOIN image_digests d ON d.id = v.image_id
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

	// Same guard as LoadListPage: avoid SQLSTATE 55000 during the
	// startup window where the unified MVs are still being populated.
	// Returns the zero summary so the caller's caches store a coherent
	// "no findings yet" entry rather than a hard error.
	if !unifiedViewsReady(ctx, db) {
		return summary, nil
	}

	// Count across both repo-side and image-side vulns. Each row in
	// vuln_canonical_assets is already one (asset_type, asset_id,
	// canonical_id) tuple with sev_rank pre-collapsed across scanner
	// variants (CVE / GHSA / BIT for the same advisory). Falls back
	// to the slow recompute when the canonical MV hasn't populated
	// yet — typically only on a fresh deploy.
	canonicalReady, _ := spamdb.VulnCanonicalViewsPopulated(ctx, db)
	if canonicalReady {
		if err := db.WithContext(ctx).Raw(`
			SELECT
				COUNT(*) FILTER (WHERE sev_rank = 1)::int AS total_critical,
				COUNT(*) FILTER (WHERE sev_rank = 2)::int AS total_high,
				COUNT(*) FILTER (WHERE sev_rank = 3)::int AS total_medium,
				COUNT(*) FILTER (WHERE sev_rank = 4)::int AS total_low,
				COUNT(*) FILTER (WHERE sev_rank = 5)::int AS total_unknown
			FROM vuln_canonical_assets
		`).Scan(&summary).Error; err != nil {
			return Summary{}, err
		}
	} else {
		// Fallback: collapse scanner variants on the fly. Same shape
		// as the previous body; ran in the wild until vuln_canonical_assets
		// landed.
		if err := db.WithContext(ctx).Raw(`
			WITH u AS (
				SELECT 'repo'::text AS asset_type, repo_id AS asset_id, vuln_id, severity
				FROM view_unified_repositories_vulnerabilities
				UNION ALL
				SELECT 'image'::text AS asset_type, image_id AS asset_id, vuln_id, severity
				FROM view_unified_image_vulnerabilities
			),
			canonical AS (
				SELECT
					u.asset_type,
					u.asset_id,
					COALESCE(vm.canonical_id, u.vuln_id) AS canonical_id,
					MIN(CASE u.severity
						WHEN 'CRITICAL' THEN 1
						WHEN 'HIGH'     THEN 2
						WHEN 'MEDIUM'   THEN 3
						WHEN 'LOW'      THEN 4
						ELSE 5
					END) AS sev_rank
				FROM u
				LEFT JOIN vuln_metadata vm ON vm.vuln_id = u.vuln_id
				GROUP BY u.asset_type, u.asset_id, COALESCE(vm.canonical_id, u.vuln_id)
			)
			SELECT
				COUNT(*) FILTER (WHERE sev_rank = 1)::int AS total_critical,
				COUNT(*) FILTER (WHERE sev_rank = 2)::int AS total_high,
				COUNT(*) FILTER (WHERE sev_rank = 3)::int AS total_medium,
				COUNT(*) FILTER (WHERE sev_rank = 4)::int AS total_low,
				COUNT(*) FILTER (WHERE sev_rank = 5)::int AS total_unknown
			FROM canonical
		`).Scan(&summary).Error; err != nil {
			return Summary{}, err
		}
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

// LoadSummaryScoped is the narrow-grant counterpart to LoadSummary.
// It recomputes severity counts and SBOM metadata against an ACL-
// scoped subset of the canonical vuln MV — used when the caller is
// not admin / global_reader and the cached cross-tenant aggregate
// would either over-share or hard-fail.
//
// repoSQL / imageSQL are full predicates against the unified-view row
// (alias `v`, columns `v.repo_id` / `v.image_id`). The body rewrites
// them to the canonical-MV column shape (asset_id, asset_type) so the
// same fragments produced by uiapi.repoSubquery / imageSubquery work
// against vuln_canonical_assets without churning every call site. See
// the contract comment on canonicalAssetWhere below.
//
// "FALSE" excludes that branch entirely — pass "FALSE" for both when
// the caller has no readable assets at all (the handler should
// short-circuit there anyway, this is belt-and-braces).
//
// Cached per (subject ACL fragments) against the MV-refresh watermark:
// two callers with identical readable sets share an entry and a rebuild
// invalidates exactly when the underlying MVs change — same scheme as
// the list and trend caches.
func LoadSummaryScoped(ctx context.Context, db *gorm.DB, repoSQL string, repoArgs []any, imageSQL string, imageArgs []any) (Summary, error) {
	if !unifiedViewsReady(ctx, db) {
		return Summary{}, nil
	}

	store := cache.NewPostgresStore(db)
	version, versionErr := querySummaryVersion(ctx, db)
	var cacheKey string
	if versionErr == nil {
		cacheKey = summaryScopedCacheKey(version, repoSQL, repoArgs, imageSQL, imageArgs)
		if entry, ok, err := cache.GetJSON[cachedSummary](ctx, store, cacheKey); err == nil && ok {
			if sameVersion(entry.Version, version) {
				return entry.Summary, nil
			}
		}
	}

	summary, err := computeSummaryScoped(ctx, db, repoSQL, repoArgs, imageSQL, imageArgs)
	if err != nil {
		return Summary{}, err
	}

	if versionErr == nil && cacheKey != "" {
		_ = cache.SetJSON(ctx, store, cacheKey, cachedSummary{Version: version, Summary: summary}, summaryCacheTTL)
	}
	return summary, nil
}

// computeSummaryScoped recomputes severity counts + SBOM metadata for an
// ACL-scoped subset, reading the pre-aggregated vuln_canonical_assets MV
// when populated and falling back to a request-time re-aggregation of the
// unified views during the bootstrap window. The repoSQL / imageSQL
// fragments are rewritten to the canonical-MV column shape via
// canonicalAssetWhere — see its contract comment.
func computeSummaryScoped(ctx context.Context, db *gorm.DB, repoSQL string, repoArgs []any, imageSQL string, imageArgs []any) (Summary, error) {
	var summary Summary
	canonicalReady, _ := spamdb.VulnCanonicalViewsPopulated(ctx, db)

	repoSQL = strings.TrimSpace(repoSQL)
	if repoSQL == "" {
		repoSQL = "FALSE"
	}
	imageSQL = strings.TrimSpace(imageSQL)
	if imageSQL == "" {
		imageSQL = "FALSE"
	}

	countArgs := append([]any{}, repoArgs...)
	countArgs = append(countArgs, imageArgs...)

	var countSQL string
	if canonicalReady {
		// Fast path: read the pre-aggregated MV through the per-asset_type
		// UNION-ALL CTE so each branch uses its partial index instead of
		// seq-scanning the whole MV (the OR predicate from
		// canonicalAssetWhere couldn't). The (asset, canonical) dedup is
		// already baked in, so this is a COUNT FILTER over the scoped set.
		cte, aclArgs := scopedAssetsCTE(repoSQL, repoArgs, imageSQL, imageArgs)
		countArgs = aclArgs
		countSQL = "WITH scoped_assets AS (" + cte + `)
			SELECT
				COUNT(*) FILTER (WHERE sev_rank = 1)::int AS total_critical,
				COUNT(*) FILTER (WHERE sev_rank = 2)::int AS total_high,
				COUNT(*) FILTER (WHERE sev_rank = 3)::int AS total_medium,
				COUNT(*) FILTER (WHERE sev_rank = 4)::int AS total_low,
				COUNT(*) FILTER (WHERE sev_rank = 5)::int AS total_unknown
			FROM scoped_assets`
	} else {
		// Fallback used during the bootstrap window where the canonical
		// MVs are still first-populating. Same canonical-aware dedup as
		// computeSummary, with the UNION inputs filtered by the caller's
		// ACL fragments.
		countSQL = fmt.Sprintf(`
			WITH u AS (
				SELECT 'repo'::text AS asset_type, v.repo_id AS asset_id, v.vuln_id, v.severity
				FROM view_unified_repositories_vulnerabilities v
				WHERE %s
				UNION ALL
				SELECT 'image'::text AS asset_type, v.image_id AS asset_id, v.vuln_id, v.severity
				FROM view_unified_image_vulnerabilities v
				WHERE %s
			),
			canonical AS (
				SELECT
					u.asset_type,
					u.asset_id,
					COALESCE(vm.canonical_id, u.vuln_id) AS canonical_id,
					MIN(CASE u.severity
						WHEN 'CRITICAL' THEN 1
						WHEN 'HIGH'     THEN 2
						WHEN 'MEDIUM'   THEN 3
						WHEN 'LOW'      THEN 4
						ELSE 5
					END) AS sev_rank
				FROM u
				LEFT JOIN vuln_metadata vm ON vm.vuln_id = u.vuln_id
				GROUP BY u.asset_type, u.asset_id, COALESCE(vm.canonical_id, u.vuln_id)
			)
			SELECT
				COUNT(*) FILTER (WHERE sev_rank = 1)::int AS total_critical,
				COUNT(*) FILTER (WHERE sev_rank = 2)::int AS total_high,
				COUNT(*) FILTER (WHERE sev_rank = 3)::int AS total_medium,
				COUNT(*) FILTER (WHERE sev_rank = 4)::int AS total_low,
				COUNT(*) FILTER (WHERE sev_rank = 5)::int AS total_unknown
			FROM canonical
		`, repoSQL, imageSQL)
		// Fallback duplicates the args (one set per UNION branch).
		countArgs = append(append([]any{}, repoArgs...), imageArgs...)
	}

	if err := db.WithContext(ctx).Raw(countSQL, countArgs...).Scan(&summary).Error; err != nil {
		return Summary{}, err
	}

	// Scoped scanned_sboms / last_scanned_at: bound SBOMs whose
	// underlying asset (repo_commit or image_digest) is in the
	// caller's readable set. The IS_PRIVATE check on repos is folded
	// into repoSQL already so public repos count for cluster-only
	// callers too.
	type scanMeta struct {
		ScannedSBOMs  int        `gorm:"column:scanned_sboms"`
		LastScannedAt *time.Time `gorm:"column:last_scanned_at"`
	}
	var meta scanMeta
	scanSQL := fmt.Sprintf(`
		WITH readable_repo_ids AS (
			SELECT v.repo_id AS id
			FROM view_unified_repositories_vulnerabilities v
			WHERE %s
		),
		readable_image_ids AS (
			SELECT v.image_id AS id
			FROM view_unified_image_vulnerabilities v
			WHERE %s
		),
		readable_sboms AS (
			SELECT DISTINCT sb.sbom_id
			FROM sbom_bindings sb
			WHERE (sb.asset_type = 'REPO_COMMIT' AND sb.asset_ref_id IN (
				SELECT rc.id FROM repo_commits rc WHERE rc.repo_id IN (SELECT id FROM readable_repo_ids)
			))
			   OR (sb.asset_type = 'IMAGE_DIGEST' AND sb.asset_ref_id IN (SELECT id FROM readable_image_ids))
		),
		ts AS (
			SELECT MAX(ssr.scanned_at) AS t
			FROM sbom_scan_results ssr
			WHERE ssr.repo_id IN (SELECT id FROM readable_repo_ids)
			UNION ALL
			SELECT MAX(isr.finished_at)
			FROM image_scan_runs isr
			WHERE isr.image_digest_id IN (SELECT id FROM readable_image_ids)
		)
		SELECT
			(SELECT COUNT(*) FROM readable_sboms)::int AS scanned_sboms,
			(SELECT MAX(t) FROM ts)                    AS last_scanned_at
	`, repoSQL, imageSQL)
	scanArgs := append([]any{}, repoArgs...)
	scanArgs = append(scanArgs, imageArgs...)
	if err := db.WithContext(ctx).Raw(scanSQL, scanArgs...).Scan(&meta).Error; err != nil {
		return Summary{}, err
	}
	summary.ScannedSBOMs = meta.ScannedSBOMs
	summary.LastScannedAt = meta.LastScannedAt
	summary.TotalVulns = summary.TotalCritical + summary.TotalHigh + summary.TotalMedium + summary.TotalLow + summary.TotalUnknown

	return summary, nil
}

func querySummaryVersion(ctx context.Context, db *gorm.DB) (summaryVersion, error) {
	// The vuln dashboard caches are a pure function of the unified/canonical
	// vuln MVs, so the MV's own last-refresh time is the correct (and cheap,
	// PK-indexed) invalidation watermark. See db.VulnViewsRefreshedAt and the
	// summaryVersion doc comment.
	at, err := spamdb.VulnViewsRefreshedAt(ctx, db)
	if err != nil {
		return summaryVersion{}, err
	}
	return summaryVersion{VulnViewsRefreshedAt: at}, nil
}

func computeRepos(ctx context.Context, db *gorm.DB) ([]RepoRow, error) {
	if !unifiedViewsReady(ctx, db) {
		return []RepoRow{}, nil
	}
	var rows []RepoRow
	// Same canonical-aware dedup as computeSummary, scoped per repo:
	// collapse (canonical, repo) pairs to one row at worst severity,
	// then bucket those rows by severity.
	if err := db.WithContext(ctx).Raw(`
		WITH canonical AS (
			SELECT
				v.repo_id,
				MAX(v.repo_slug) AS repo_slug,
				COALESCE(vm.canonical_id, v.vuln_id) AS canonical_id,
				MIN(CASE v.severity
					WHEN 'CRITICAL' THEN 1
					WHEN 'HIGH'     THEN 2
					WHEN 'MEDIUM'   THEN 3
					WHEN 'LOW'      THEN 4
					ELSE 5
				END) AS sev_rank,
				MAX(v.scanned_at) AS scanned_at
			FROM view_unified_repositories_vulnerabilities v
			LEFT JOIN vuln_metadata vm ON vm.vuln_id = v.vuln_id
			GROUP BY v.repo_id, COALESCE(vm.canonical_id, v.vuln_id)
		)
		SELECT
			repo_id,
			MAX(repo_slug) AS repo_slug,
			COUNT(*) FILTER (WHERE sev_rank = 1)::int AS critical_count,
			COUNT(*) FILTER (WHERE sev_rank = 2)::int AS high_count,
			COUNT(*) FILTER (WHERE sev_rank = 3)::int AS medium_count,
			COUNT(*) FILTER (WHERE sev_rank = 4)::int AS low_count,
			COUNT(*) FILTER (WHERE sev_rank = 5)::int AS unknown_count,
			MAX(scanned_at) AS last_scanned_at
		FROM canonical
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
	return sameTime(a.VulnViewsRefreshedAt, b.VulnViewsRefreshedAt)
}

func sameTime(a, b *time.Time) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return a.Equal(*b)
}
