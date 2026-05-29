package assetrisk

import (
	"context"
	"log"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	spamdb "github.com/NorskHelsenett/spam/internal/db"
	"gorm.io/gorm"
)

const (
	// refreshMaxRuntime caps a single REFRESH attempt. The MV body
	// pulls in every repo, image, and cluster with their full risk
	// signals (vuln counts, secret counts, dep-health, exposure) in
	// one CTE — at fleet scale this can run 5-15 minutes. The previous
	// 2-minute cap was tighter than the actual query, so the goroutine
	// loop logged "context deadline exceeded" forever and the MV
	// stayed unpopulated. 30 minutes leaves headroom for further
	// growth before we need to slice the body up.
	refreshMaxRuntime = 30 * time.Minute

	// Default page size for the watch tier. The fix_now / this_week
	// tiers are returned in full (they're operator-actionable, sized
	// by reality, not pagination).
	defaultWatchLimit = 50
	maxWatchLimit     = 500

	// fixNowCap / thisWeekCap bound the size of the urgent tiers in
	// pathological deployments. If you legitimately have 200 fix_now
	// items something else is on fire — paginate later.
	fixNowCap   = 100
	thisWeekCap = 200

	// suppressedCap bounds the "currently acknowledged" section so a
	// fleet with thousands of long-lived snoozes doesn't bloat the
	// dashboard payload. Users hunting older acks query the breakdown
	// endpoint per asset.
	suppressedCap = 100
)

// Scope is the header strip on /app — operator's inventory + count of
// items needing attention, post-ACL.
//
// FixNowTotal / ThisWeekTotal report the *true* tier population before
// the response-side caps (fixNowCap / thisWeekCap) trim the row arrays.
// The dashboard renders these so an operator with 850 fix_now items
// doesn't see a misleading "100" that's actually the cap.
//
// AvgTrust is computed server-side over every actionable row
// (fix_now + this_week + watch, pre-cap) so it doesn't drift as the
// operator paginates through watch on the client.
type Scope struct {
	Clusters        int        `json:"clusters"`
	Repos           int        `json:"repos"`
	Images          int        `json:"images"`
	NeedsAttention  int        `json:"needs_attention"`
	FixNowTotal     int        `json:"fix_now_total"`
	ThisWeekTotal   int        `json:"this_week_total"`
	AvgTrust        int        `json:"avg_trust"`
	ViewRefreshedAt *time.Time `json:"view_refreshed_at,omitempty"`
}

// TriageRow is one asset's row in the response. Embeds Signals so the
// raw inputs travel with the computed scores — the UI can render the
// "show your work" expand panel without a separate fetch.
type TriageRow struct {
	Signals
	ThreatScore int      `json:"threat_score"`
	TrustScore  int      `json:"trust_score"`
	TrustGrade  string   `json:"trust_grade"`
	Tier        string   `json:"tier"`
	Reasons     []Reason `json:"reasons"`
}

// AckedRow surfaces an asset whose live ack hides it from the main
// tiers. The frontend renders these in a separate "Suppressed" section
// so operators can see what's been muted and revoke if needed —
// without polluting the active queue.
type AckedRow struct {
	Signals
	ThreatScore int             `json:"threat_score"`
	TrustScore  int             `json:"trust_score"`
	TrustGrade  string          `json:"trust_grade"`
	Tier        string          `json:"tier"`
	Reasons     []Reason        `json:"reasons"`
	Ack         Acknowledgment  `json:"ack"`
}

// WatchSection paginates the long tail of "warnings, but not urgent"
// assets. Counts are unfiltered; rows is the page slice.
type WatchSection struct {
	Counts WatchCounts `json:"counts"`
	Limit  int         `json:"limit"`
	Offset int         `json:"offset"`
	Rows   []TriageRow `json:"rows"`
}

type WatchCounts struct {
	Total   int `json:"total"`
	Repo    int `json:"repo"`
	Image   int `json:"image"`
	Cluster int `json:"cluster"`
}

// TriageResponse is the wire shape of /api/triage. Single fat endpoint
// — page is small enough that splitting it would just add round trips.
type TriageResponse struct {
	Scope    Scope        `json:"scope"`
	FixNow   []TriageRow  `json:"fix_now"`
	ThisWeek []TriageRow  `json:"this_week"`
	Watch    WatchSection `json:"watch"`
	// Suppressed lists assets whose live ack hides them from the
	// active tiers. Empty when there are no live acks in the
	// caller's scope. Capped at suppressedCap to keep the wire size
	// bounded; the order is newest ack first.
	Suppressed []AckedRow `json:"suppressed"`
}

// TriageParams is what the handler passes in: ACL fragments per asset
// branch + watch-tier pagination/search.
//
// Each branch's SQL fragment is interpolated into a WHERE predicate
// against the asset_risk row. Use "TRUE" for unrestricted, "FALSE" to
// exclude the entire branch.
type TriageParams struct {
	WatchLimit  int
	WatchOffset int
	WatchSearch string

	RepoSQL    string
	RepoArgs   []any
	ImageSQL   string
	ImageArgs  []any
	ClusterSQL string
	ClusterArgs []any
}

// refreshGate coalesces concurrent TriggerRefresh calls — same pattern
// as vulnmetrics: one inflight refresh, one pending bit.
var refreshGate struct {
	mu       sync.Mutex
	inflight bool
	pending  bool
}

// assetRiskReadyCache flips to true the first time the MV is observed
// populated and stays true. Reset on process restart.
var assetRiskReadyCache atomic.Bool

func assetRiskReady(ctx context.Context, db *gorm.DB) bool {
	if assetRiskReadyCache.Load() {
		return true
	}
	ok, err := spamdb.AssetRiskViewPopulated(ctx, db)
	if err != nil || !ok {
		return false
	}
	assetRiskReadyCache.Store(true)
	return true
}

// EnsureFirstPopulate blocks until the asset_risk MV is populated. Call
// after vulnmetrics + hostexposure first-populates have completed —
// asset_risk's body joins view_unified_*_vulnerabilities and
// exposed_digests, so a refresh issued before those are populated
// raises SQLSTATE 55000 ("materialized view has not been populated")
// and the gate's pending bit is local-only, so nothing retries it.
//
// Multi-replica safe via RefreshAssetRiskView's advisory lock. Returns
// on ctx cancel.
func EnsureFirstPopulate(ctx context.Context, db *gorm.DB) error {
	backoff := 2 * time.Second
	for {
		if assetRiskReady(ctx, db) {
			return nil
		}
		if err := spamdb.RefreshAssetRiskView(ctx, db); err != nil && err != spamdb.ErrRefreshLockHeld {
			log.Printf("assetrisk: first populate refresh: %v", err)
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

// TriggerRefresh proactively rebuilds the asset_risk MV in the
// background. Call from any signal-source change hook (scan
// completion, secret-probe verdict, cluster-record write) so the next
// /api/triage request lands on a warm view. Safe to spam — the gate
// coalesces concurrent calls into one inflight + one pending.
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
			ctx, cancel := context.WithTimeout(context.Background(), refreshMaxRuntime)
			if err := spamdb.RefreshAssetRiskView(ctx, db); err != nil && err != spamdb.ErrRefreshLockHeld {
				log.Printf("assetrisk: background refresh: %v", err)
			}
			// Drift check: re-fingerprint live "suppress_until_change"
			// acks against the freshly refreshed asset_risk rows and
			// revoke any whose inputs moved. Skipped on a held lock
			// (another replica did the refresh and will handle drift
			// on its side). Bounded to a separate, shorter timeout so
			// a slow drift sweep can't pin the refresh goroutine.
			driftCtx, driftCancel := context.WithTimeout(context.Background(), 2*time.Minute)
			if err := revokeDriftedAcks(driftCtx, db); err != nil {
				log.Printf("assetrisk: revokeDrift: %v", err)
			}
			driftCancel()
			cancel()

			refreshGate.mu.Lock()
			if !refreshGate.pending {
				refreshGate.inflight = false
				refreshGate.mu.Unlock()
				return
			}
			refreshGate.pending = false
			refreshGate.mu.Unlock()
		}
	}()
}

// revokeDriftedAcks reads the post-refresh signals for every asset that
// has a live suppress_until_change ack, fingerprints them, and revokes
// the ones whose fingerprint moved. Restricting the scan to assets
// that have an active ack avoids a full pass over asset_risk on every
// refresh — there are typically a few hundred acks at most.
func revokeDriftedAcks(ctx context.Context, db *gorm.DB) error {
	var acks []Acknowledgment
	err := db.WithContext(ctx).
		Where("revoked_at IS NULL AND action = ?", AckActionSuppress).
		Find(&acks).Error
	if err != nil {
		return err
	}
	if len(acks) == 0 {
		return nil
	}
	types := make([]string, 0, len(acks))
	ids := make([]string, 0, len(acks))
	for _, a := range acks {
		types = append(types, a.AssetType)
		ids = append(ids, a.AssetID)
	}
	// JSON-bind the parallel key arrays — see marshalKeyArrays /
	// LiveAckForAssets for why a raw []string can't feed UNNEST(?::text[]).
	typesJSON, idsJSON, err := marshalKeyArrays(types, ids)
	if err != nil {
		return err
	}
	var current []Signals
	err = db.WithContext(ctx).Raw(`
		SELECT
			ar.asset_type, ar.asset_id, ar.asset_slug,
			COALESCE(d.digest, '') AS image_digest,
			critical_count, high_count, kev_count, epss_max,
			has_fix_for_critical, active_secret_count, internet_exposed,
			signed_commits_pct, image_signed, scan_age_days, last_scan_at, has_sbom,
			worst_dep_health_score, archived_dep_count, deprecated_dep_count,
			max_major_behind, major_behind_dep_count
		FROM asset_risk ar
		LEFT JOIN image_digests d ON ar.asset_type = 'image' AND ar.asset_id = d.id::text
		WHERE (ar.asset_type, ar.asset_id) IN (
		    SELECT * FROM UNNEST(
		      ARRAY(SELECT jsonb_array_elements_text(?::jsonb)),
		      ARRAY(SELECT jsonb_array_elements_text(?::jsonb))
		    )
		  )
	`, typesJSON, idsJSON).Scan(&current).Error
	if err != nil {
		return err
	}
	_, err = RevokeOnDrift(ctx, db, current)
	return err
}

// LoadTriage reads the asset_risk MV through the caller's ACL filter,
// computes scores in Go, and partitions into tiers. The MV is small
// (one row per asset) so we fetch all post-ACL rows and rank them in
// memory rather than encoding the scoring formulas in SQL — keeps the
// formula in one place and trivially testable.
func LoadTriage(ctx context.Context, db *gorm.DB, p TriageParams) (TriageResponse, error) {
	resp := TriageResponse{
		FixNow:     []TriageRow{},
		ThisWeek:   []TriageRow{},
		Watch:      WatchSection{Rows: []TriageRow{}, Limit: p.watchLimitOrDefault(), Offset: p.WatchOffset},
		Suppressed: []AckedRow{},
	}

	if !assetRiskReady(ctx, db) {
		return resp, nil
	}

	// Pull every visible row in one shot, ACL-filtered. The MV's
	// (asset_type, asset_id) unique index keeps this a single index
	// scan per branch.
	rows, refreshedAt, err := loadAllRows(ctx, db, p)
	if err != nil {
		return resp, err
	}

	// Inventory totals are per branch, post-ACL.
	for _, r := range rows {
		switch r.AssetType {
		case "repo":
			resp.Scope.Repos++
		case "image":
			resp.Scope.Images++
		case "cluster":
			resp.Scope.Clusters++
		}
	}

	// Fetch live acks for every visible asset in one round-trip so the
	// tier loop can route suppressed rows into resp.Suppressed instead
	// of fix_now/this_week/watch. Snooze expiry is enforced server-side
	// in LiveAckForAssets — a snooze that lapsed mid-day re-surfaces
	// immediately on the next /api/triage call without waiting for the
	// MV refresh.
	keys := make([]AssetKey, 0, len(rows))
	for _, r := range rows {
		keys = append(keys, AssetKey{Type: r.AssetType, ID: r.AssetID})
	}
	acks, err := LiveAckForAssets(ctx, db, keys)
	if err != nil {
		return resp, err
	}

	// Score every row, partition by tier. Suppressed rows skip the
	// active tiers but still get scored — the frontend renders their
	// would-be tier alongside the ack badge so the operator can judge
	// the suppression's cost.
	var watchAll []TriageRow
	var suppressedAll []AckedRow
	for _, sig := range rows {
		row := TriageRow{
			Signals:     sig,
			ThreatScore: ThreatScore(sig),
			TrustScore:  TrustScore(sig),
			Tier:        Tier(sig),
			Reasons:     Reasons(sig),
		}
		row.TrustGrade = TrustGrade(row.TrustScore)
		if ack, ok := acks[AssetKey{Type: sig.AssetType, ID: sig.AssetID}]; ok {
			suppressedAll = append(suppressedAll, AckedRow{
				Signals:     row.Signals,
				ThreatScore: row.ThreatScore,
				TrustScore:  row.TrustScore,
				TrustGrade:  row.TrustGrade,
				Tier:        row.Tier,
				Reasons:     row.Reasons,
				Ack:         ack,
			})
			continue
		}
		switch row.Tier {
		case TierFixNow:
			resp.FixNow = append(resp.FixNow, row)
		case TierThisWeek:
			resp.ThisWeek = append(resp.ThisWeek, row)
		case TierWatch:
			watchAll = append(watchAll, row)
		}
	}

	sort.SliceStable(suppressedAll, func(i, j int) bool {
		return suppressedAll[i].Ack.CreatedAt.After(suppressedAll[j].Ack.CreatedAt)
	})
	if len(suppressedAll) > suppressedCap {
		suppressedAll = suppressedAll[:suppressedCap]
	}
	resp.Suppressed = suppressedAll

	rankTriage(resp.FixNow)
	rankTriage(resp.ThisWeek)
	rankTriage(watchAll)

	// Capture true tier totals BEFORE the response-side caps trim the
	// row arrays. The dashboard reads these so the header strip shows
	// the real population — the row arrays are still capped to keep
	// the response payload bounded.
	resp.Scope.FixNowTotal = len(resp.FixNow)
	resp.Scope.ThisWeekTotal = len(resp.ThisWeek)

	// AvgTrust over every actionable row (fix_now + this_week + watch
	// pre-pagination). Computed here so it stays stable as the operator
	// pages through the watch tier on the client — the previous
	// client-side average drifted because it summed only the current
	// watch page (default 50 of N).
	if total := resp.Scope.FixNowTotal + resp.Scope.ThisWeekTotal + len(watchAll); total > 0 {
		var sum int
		for _, r := range resp.FixNow {
			sum += r.TrustScore
		}
		for _, r := range resp.ThisWeek {
			sum += r.TrustScore
		}
		for _, r := range watchAll {
			sum += r.TrustScore
		}
		resp.Scope.AvgTrust = sum / total
	}

	if len(resp.FixNow) > fixNowCap {
		resp.FixNow = resp.FixNow[:fixNowCap]
	}
	if len(resp.ThisWeek) > thisWeekCap {
		resp.ThisWeek = resp.ThisWeek[:thisWeekCap]
	}

	// Watch tier search is applied client-side over the in-memory
	// page since the post-ACL set is small. If it ever bloats, push
	// the ILIKE into loadAllRows.
	if q := strings.TrimSpace(p.WatchSearch); q != "" {
		needle := strings.ToLower(q)
		filtered := watchAll[:0]
		for _, r := range watchAll {
			if strings.Contains(strings.ToLower(r.AssetSlug), needle) {
				filtered = append(filtered, r)
			}
		}
		watchAll = filtered
	}

	resp.Watch.Counts.Total = len(watchAll)
	for _, r := range watchAll {
		switch r.AssetType {
		case "repo":
			resp.Watch.Counts.Repo++
		case "image":
			resp.Watch.Counts.Image++
		case "cluster":
			resp.Watch.Counts.Cluster++
		}
	}

	off := clamp(p.WatchOffset, 0, len(watchAll))
	end := clamp(off+resp.Watch.Limit, 0, len(watchAll))
	resp.Watch.Rows = watchAll[off:end]

	// NeedsAttention reports the un-capped sum so "300 across 6754" is
	// honest — the previous len(FixNow)+len(ThisWeek) was post-cap and
	// silently flat-lined at 300 once both tiers hit their caps.
	resp.Scope.NeedsAttention = resp.Scope.FixNowTotal + resp.Scope.ThisWeekTotal
	resp.Scope.ViewRefreshedAt = refreshedAt

	return resp, nil
}

// rankTriage sorts a tier's rows by composite urgency: higher Threat
// first, then lower Trust (worse trust is worse), then asset_slug for
// stable ordering between requests.
func rankTriage(rows []TriageRow) {
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].ThreatScore != rows[j].ThreatScore {
			return rows[i].ThreatScore > rows[j].ThreatScore
		}
		if rows[i].TrustScore != rows[j].TrustScore {
			return rows[i].TrustScore < rows[j].TrustScore
		}
		return rows[i].AssetSlug < rows[j].AssetSlug
	})
}

// loadAllRows fetches every visible asset_risk row by composing the
// three ACL fragments with OR. Each branch's fragment scopes the
// asset_type WHERE so the index on (asset_type, asset_id) does the
// work.
func loadAllRows(ctx context.Context, db *gorm.DB, p TriageParams) ([]Signals, *time.Time, error) {
	repoSQL := p.RepoSQL
	if repoSQL == "" {
		repoSQL = "FALSE"
	}
	imageSQL := p.ImageSQL
	if imageSQL == "" {
		imageSQL = "FALSE"
	}
	clusterSQL := p.ClusterSQL
	if clusterSQL == "" {
		clusterSQL = "FALSE"
	}

	args := []any{}
	args = append(args, p.RepoArgs...)
	args = append(args, p.ImageArgs...)
	args = append(args, p.ClusterArgs...)

	q := `
		SELECT
			ar.asset_type, ar.asset_id, ar.asset_slug,
			COALESCE(d.digest, '') AS image_digest,
			critical_count, high_count, kev_count, epss_max,
			has_fix_for_critical, active_secret_count, internet_exposed,
			signed_commits_pct, image_signed, scan_age_days, last_scan_at, has_sbom,
			worst_dep_health_score, archived_dep_count, deprecated_dep_count,
			max_major_behind, major_behind_dep_count
		FROM asset_risk ar
		LEFT JOIN image_digests d ON ar.asset_type = 'image' AND ar.asset_id = d.id
		WHERE
		  (ar.asset_type = 'repo'    AND ` + repoSQL + `)
		   OR (ar.asset_type = 'image'   AND ` + imageSQL + `)
		   OR (ar.asset_type = 'cluster' AND ` + clusterSQL + `)
	`

	var rows []Signals
	if err := db.WithContext(ctx).Raw(q, args...).Scan(&rows).Error; err != nil {
		return nil, nil, err
	}

	// MV last refresh — used to display "data as of …" in the UI.
	var refreshedAt *time.Time
	db.WithContext(ctx).Raw(
		"SELECT refreshed_at FROM materialized_view_refreshes WHERE name = ?",
		"asset_risk",
	).Scan(&refreshedAt)

	return rows, refreshedAt, nil
}

func (p TriageParams) watchLimitOrDefault() int {
	if p.WatchLimit <= 0 {
		return defaultWatchLimit
	}
	if p.WatchLimit > maxWatchLimit {
		return maxWatchLimit
	}
	return p.WatchLimit
}
