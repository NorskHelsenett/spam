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
	// keep serving the previous ordering until their 7-day TTL.
	listCachePrefix   = "vuln:list:v4:"
	summaryCacheTTL   = 7 * 24 * time.Hour
	refreshMaxRuntime = 2 * time.Minute
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
	return Refresh(ctx, db, time.Now().UTC())
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
		if err := spamdb.RefreshVulnUnifiedViews(ctx, db); err != nil && err != spamdb.ErrRefreshLockHeld {
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
			if _, err := Refresh(ctx, db, time.Now().UTC()); err != nil {
				log.Printf("vulnmetrics: background refresh: %v", err)
				// Skipping the assetrisk cascade is deliberate — asset_risk
				// reads from the vuln_unified MVs, so refreshing it against
				// data we just failed to recompute would record a stale
				// snapshot. The log line makes the staleness visible to ops
				// instead of silently letting asset_risk drift.
				log.Printf("vulnmetrics: skipping assetrisk cascade (vulnmetrics refresh failed)")
			} else {
				// asset_risk reads the unified vulnerability MVs. Cascade
				// after the vuln refresh has had a chance to land instead
				// of letting scan hooks trigger both families in parallel
				// against mismatched snapshots.
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

func Refresh(ctx context.Context, db *gorm.DB, capturedAt time.Time) (Summary, error) {
	// Refresh the unified vuln MVs first so computeSummary / computeRepos
	// observe the freshest scan data. ErrRefreshLockHeld means another
	// replica is already refreshing — its result will land before ours
	// would have, so treat it as a no-op rather than an error. Other
	// failures fall through; computeSummary will then either see stale
	// data (acceptable) or, on first start, return zero-value rows
	// (handled by the unpopulated guard in LoadSummary / LoadListPage).
	if err := spamdb.RefreshVulnUnifiedViews(ctx, db); err != nil && err != spamdb.ErrRefreshLockHeld {
		log.Printf("vulnmetrics: refresh unified views: %v", err)
	}

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
// (scan / OSV / VEX / image-scan watermarks) as LoadSummary so the cache
// drops the moment any scan activity could have introduced new values.
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

// LoadListPage returns a paginated page of grouped vulnerabilities,
// plus the total group count for the same filters. Cached per
// (version, filters, ACL scope, page); invalidated implicitly via
// summaryVersion — any scan / OSV / VEX / image-scan completion
// changes the version hash, so stale keys are orphaned and expire
// via TTL. Fresh after every scan without a manual bust.
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
					'type', asset_type, 'id', asset_id, 'slug', asset_slug
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
		ORDER BY (kev.cve_id IS NOT NULL)        DESC,
		         COALESCE(epss.score, 0)         DESC,
		         g.sev_rank                      ASC,
		         g.cve_year                      DESC NULLS LAST,
		         g.vuln_id                       ASC
		LIMIT ? OFFSET ?
	`, base, whereClause)

	groupArgs := append([]any{}, args...)
	groupArgs = append(groupArgs, whereArgs...)
	groupArgs = append(groupArgs, p.Limit, p.Offset)

	type groupRow struct {
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

	// One bulk metadata lookup serves two purposes for the page:
	//   - Aliases per group so the UI can show cross-references
	//     (CVE ↔ GHSA ↔ BIT) beside the canonical id.
	//   - OSV affected-ranges data for the fix-version override —
	//     scanners sometimes report the first range's fix on multi-
	//     interval advisories even when the installed version lives
	//     in a later interval (valkey 8.1.3-0 getting fix=7.2.11 when
	//     the applicable fix is 8.1.4).
	//
	// items[i].VulnID is the canonical from the GROUP BY, so we
	// query MetadataForMany which matches on canonical_id OR vuln_id.
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
				// Aliases: strip the canonical itself from the list
				// shown as cross-references.
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
				// Fix-version override: use OSV's own range data when
				// available. Scanner value stays when no OSV affected
				// entry matches the package / installed version.
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

	resp := VulnListResponse{
		Total:  total,
		Limit:  p.Limit,
		Offset: p.Offset,
		Items:  items,
	}

	if versionErr == nil && cacheKey != "" {
		_ = cache.SetJSON(ctx, store, cacheKey, cachedListEntry{
			Version:  version,
			Response: resp,
		}, summaryCacheTTL)
	}

	return resp, nil
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
			v.title, v.description, v.source, v.cve_year
		FROM view_unified_repositories_vulnerabilities v
		WHERE %s
		UNION ALL
		SELECT
			'image'::text                               AS asset_type,
			v.image_id                                  AS asset_id,
			v.image_slug                                AS asset_slug,
			v.vuln_id, v.severity, v.pkg_name,
			v.installed_version, v.fixed_version,
			v.title, v.description, v.source, v.cve_year
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

	// Same guard as LoadListPage: avoid SQLSTATE 55000 during the
	// startup window where the unified MVs are still being populated.
	// Returns the zero summary so the caller's caches store a coherent
	// "no findings yet" entry rather than a hard error.
	if !unifiedViewsReady(ctx, db) {
		return summary, nil
	}

	// Count across both repo-side and image-side vulns, collapsing
	// CVE / GHSA / BIT variants of the same advisory to one row per
	// (canonical, asset). Scanners occasionally store an advisory
	// twice under different prefixes — that double-counts severity
	// totals unless we dedupe here.
	//
	// MIN(sev_rank) picks the worst severity reported for each
	// (canonical, asset) pair when the two prefixes disagree, which
	// matches the principle of "report the most serious view".
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
