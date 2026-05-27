package uiapi

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/NorskHelsenett/spam/internal/auth"
	"github.com/NorskHelsenett/spam/internal/cache"
	"github.com/NorskHelsenett/spam/internal/secretprobe"
	"gorm.io/gorm"
)

const (
	secretsCacheTTL      = 24 * time.Hour
	secretsTableCacheKey = "secrets:dashboard:table"
	secretsTrendCacheKey = "secrets:dashboard:trend"
	secretsStatsCacheKey = "secrets:dashboard:stats"
)

// secretsCacheEntry wraps a cached response with the run_secrets watermark
// so we can detect when new scan data has arrived and the cache is stale.
type secretsCacheEntry[T any] struct {
	Watermark time.Time `json:"watermark"`
	Response  T         `json:"response"`
}

var secretsTableRefreshing atomic.Bool
var secretsTrendRefreshing atomic.Bool
var secretsStatsRefreshing atomic.Bool

// secretsWatermark returns the latest run_secrets created_at timestamp,
// used to invalidate cached dashboard data when new scans complete.
func secretsWatermark(ctx context.Context, db *gorm.DB) time.Time {
	var t time.Time
	db.WithContext(ctx).Raw(
		"SELECT COALESCE(MAX(created_at), TIMESTAMPTZ 'epoch') FROM run_secrets",
	).Scan(&t)
	return t
}

// SecretTableRow represents a row in the secrets datatable.
type SecretTableRow struct {
	Repo               string    `json:"repo"`
	RepoID             string    `json:"repo_id"`
	Provider           string    `json:"provider"`
	ProviderName       string    `json:"provider_name"`
	IsPrivate          bool      `json:"is_private"`
	SecretType         string    `json:"secret_type"`
	UniqueFindingCount int64     `json:"unique_finding_count"`
	LastScanned        time.Time `json:"last_scanned"`
}

// SecretDistributionRow represents a row in the secrets donut chart.
type SecretDistributionRow struct {
	SecretType   string `json:"secret_type"`
	FindingCount int64  `json:"finding_count"`
}

// SecretsDashboardTableHandler returns per-repo secret type counts for the datatable.
//
// GET /api/secrets/table
func SecretsDashboardTableHandler(db *gorm.DB, authService *auth.Service, c cache.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if requireAuth(w, r, authService) == nil {
			return
		}

		watermark := secretsWatermark(r.Context(), db)

		if entry, ok, _ := cache.GetJSON[secretsCacheEntry[[]SecretTableRow]](r.Context(), c, secretsTableCacheKey); ok {
			if !watermark.IsZero() && !entry.Watermark.Before(watermark) {
				writeJSON(w, http.StatusOK, entry.Response)
				return
			}
			writeJSON(w, http.StatusOK, entry.Response)
			go func() {
				if !secretsTableRefreshing.CompareAndSwap(false, true) {
					return
				}
				defer secretsTableRefreshing.Store(false)
				ctx := context.Background()
				rows, err := computeSecretsTable(ctx, db)
				if err != nil {
					log.Printf("secrets table background refresh: %v", err)
					return
				}
				_ = maybeStoreSecretsCache(ctx, c, secretsTableCacheKey, watermark, rows)
			}()
			return
		}

		rows, err := computeSecretsTable(r.Context(), db)
		if err != nil {
			http.Error(w, "failed to load secrets table", http.StatusInternalServerError)
			return
		}
		_ = maybeStoreSecretsCache(r.Context(), c, secretsTableCacheKey, watermark, rows)
		writeJSON(w, http.StatusOK, rows)
	}
}

func computeSecretsTable(ctx context.Context, db *gorm.DB) ([]SecretTableRow, error) {
	query := `
WITH latest_repo_secrets AS (
  SELECT DISTINCT ON (rs.repo_id)
    rs.repo_id,
    rs.findings,
    rs.created_at
  FROM run_secrets rs
  JOIN repos r ON r.id = rs.repo_id
  LEFT JOIN provider_instances pi ON pi.id = r.provider_instance_id
  WHERE rs.repo_id IS NOT NULL
    AND rs.repo_id <> ''
    AND (pi.id IS NULL OR pi.enabled = true)
  ORDER BY rs.repo_id, rs.created_at DESC
),
deduped_findings AS (
  SELECT DISTINCT
    lrs.repo_id,
    lrs.created_at AS last_scanned,
    COALESCE(finding->>'RuleID', 'unknown') AS secret_type,
    COALESCE(finding->>'Match', '') AS match,
    COALESCE(finding->>'Secret', '') AS secret,
    COALESCE(
      NULLIF(finding->>'Fingerprint', ''),
      md5(
        concat_ws(
          '|',
          COALESCE(finding->>'RuleID', ''),
          COALESCE(finding->>'Description', ''),
          COALESCE(finding->>'File', ''),
          COALESCE(finding->>'StartLine', ''),
          COALESCE(finding->>'Match', ''),
          COALESCE(finding->>'Secret', '')
        )
      )
    ) AS dedupe_key
  FROM latest_repo_secrets lrs
  CROSS JOIN LATERAL jsonb_array_elements(COALESCE(lrs.findings, '[]'::jsonb)) AS finding
)
SELECT
  RTRIM(
    COALESCE(
      pi.base_url,
      CASE r.provider
        WHEN 'github' THEN 'https://github.com'
        WHEN 'gitlab' THEN 'https://gitlab.com'
        ELSE ''
      END
    ),
    '/'
  ) || '/' || r.org || '/' || r.slug || '.git' AS repo,
  r.id AS repo_id,
  r.provider AS provider,
  COALESCE(pi.display_name, r.provider) AS provider_name,
  r.is_private AS is_private,
  df.secret_type,
  df.match,
  df.secret,
  df.last_scanned
FROM deduped_findings df
JOIN repos r
  ON r.id = df.repo_id
LEFT JOIN provider_instances pi
  ON pi.id = r.provider_instance_id
ORDER BY repo ASC, df.secret_type ASC`

	type rawRow struct {
		Repo         string    `gorm:"column:repo"`
		RepoID       string    `gorm:"column:repo_id"`
		Provider     string    `gorm:"column:provider"`
		ProviderName string    `gorm:"column:provider_name"`
		IsPrivate    bool      `gorm:"column:is_private"`
		SecretType   string    `gorm:"column:secret_type"`
		Match        string    `gorm:"column:match"`
		Secret       string    `gorm:"column:secret"`
		LastScanned  time.Time `gorm:"column:last_scanned"`
	}
	var raw []rawRow
	if err := db.WithContext(ctx).Raw(query).Scan(&raw).Error; err != nil {
		return nil, err
	}

	// Compute hashes and look up dismissed secrets.
	hashes := make([]string, len(raw))
	for i, r := range raw {
		s := secretprobe.ExtractSecret(r.Match)
		if r.Secret != "" {
			s = secretprobe.ExtractSecret(r.Secret)
		}
		hashes[i] = secretprobe.SecretHash(s)
	}
	dismissed := map[string]bool{}
	if len(hashes) > 0 {
		var dismissedHashes []string
		db.WithContext(ctx).
			Model(&secretprobe.SecretDismissal{}).
			Where("secret_hash IN ?", hashes).
			Pluck("secret_hash", &dismissedHashes)
		for _, h := range dismissedHashes {
			dismissed[h] = true
		}
	}

	// Aggregate per repo+type, excluding dismissed.
	type groupKey struct {
		Repo         string
		RepoID       string
		Provider     string
		ProviderName string
		IsPrivate    bool
		SecretType   string
	}
	type groupVal struct {
		Count       int64
		LastScanned time.Time
	}
	groups := map[groupKey]*groupVal{}
	for i, r := range raw {
		if dismissed[hashes[i]] {
			continue
		}
		k := groupKey{r.Repo, r.RepoID, r.Provider, r.ProviderName, r.IsPrivate, r.SecretType}
		if g, ok := groups[k]; ok {
			g.Count++
			if r.LastScanned.After(g.LastScanned) {
				g.LastScanned = r.LastScanned
			}
		} else {
			groups[k] = &groupVal{Count: 1, LastScanned: r.LastScanned}
		}
	}

	rows := make([]SecretTableRow, 0, len(groups))
	for k, v := range groups {
		rows = append(rows, SecretTableRow{
			Repo:               k.Repo,
			RepoID:             k.RepoID,
			Provider:           k.Provider,
			ProviderName:       k.ProviderName,
			IsPrivate:          k.IsPrivate,
			SecretType:         k.SecretType,
			UniqueFindingCount: v.Count,
			LastScanned:        v.LastScanned,
		})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Repo != rows[j].Repo {
			return rows[i].Repo < rows[j].Repo
		}
		return rows[i].SecretType < rows[j].SecretType
	})
	return rows, nil
}

// SecretTrendRow is a single data point for the secrets trend chart.
type SecretTrendRow struct {
	Date       string `json:"date"`
	SecretType string `json:"secret_type"`
	Count      int64  `json:"count"`
}

// SecretsDashboardTrendHandler returns daily secret-type counts over the last 30 days,
// grouping everything outside the top-5 types into "other".
//
// GET /api/secrets/trend
func SecretsDashboardTrendHandler(db *gorm.DB, authService *auth.Service, c cache.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if requireAuth(w, r, authService) == nil {
			return
		}

		watermark := secretsWatermark(r.Context(), db)

		if entry, ok, _ := cache.GetJSON[secretsCacheEntry[[]SecretTrendRow]](r.Context(), c, secretsTrendCacheKey); ok {
			if !watermark.IsZero() && !entry.Watermark.Before(watermark) {
				writeJSON(w, http.StatusOK, entry.Response)
				return
			}
			writeJSON(w, http.StatusOK, entry.Response)
			go func() {
				if !secretsTrendRefreshing.CompareAndSwap(false, true) {
					return
				}
				defer secretsTrendRefreshing.Store(false)
				ctx := context.Background()
				rows, err := computeSecretsTrend(ctx, db)
				if err != nil {
					log.Printf("secrets trend background refresh: %v", err)
					return
				}
				_ = maybeStoreSecretsCache(ctx, c, secretsTrendCacheKey, watermark, rows)
			}()
			return
		}

		rows, err := computeSecretsTrend(r.Context(), db)
		if err != nil {
			http.Error(w, "failed to load secrets trend", http.StatusInternalServerError)
			return
		}
		_ = maybeStoreSecretsCache(r.Context(), c, secretsTrendCacheKey, watermark, rows)
		writeJSON(w, http.StatusOK, rows)
	}
}

func computeSecretsTrend(ctx context.Context, db *gorm.DB) ([]SecretTrendRow, error) {
	// Earlier revisions of this function forward-filled the latest
	// scan's full findings array across every day in the 30-day
	// window in SQL, then expanded the jsonb array per row. At fleet
	// scale that became repos × days × findings_per_scan rows — the
	// slow_query log showed ~19M rows per call and the handler 504'd
	// in production.
	//
	// The rewrite expands findings once per actual scan (one row per
	// repo×scan_day×finding, capped to the per-day DISTINCT-ON pick
	// of the latest scan for that day) and forward-fills in Go. SQL
	// stays O(scans × findings_per_scan); Go owns the date-axis
	// projection across the visible window. The pre-window lookback
	// keeps repos that haven't scanned in the current 30 days but
	// scanned in the prior month — without it, the first days of
	// the window flat-line at zero for slow-scanning repos.
	const lookbackDays = 90
	query := `
SELECT
    lpd.repo_id AS repo_id,
    lpd.scan_day::text AS scan_day,
    COALESCE(finding->>'RuleID', 'unknown') AS secret_type,
    COALESCE(finding->>'Match', '') AS match,
    COALESCE(finding->>'Secret', '') AS secret,
    COALESCE(
        NULLIF(finding->>'Fingerprint', ''),
        md5(concat_ws('|',
            COALESCE(finding->>'RuleID', ''),
            COALESCE(finding->>'Description', ''),
            COALESCE(finding->>'File', ''),
            COALESCE(finding->>'StartLine', ''),
            COALESCE(finding->>'Match', ''),
            COALESCE(finding->>'Secret', '')
        ))
    ) AS dedupe_key
FROM (
    SELECT DISTINCT ON (rs.repo_id, date_trunc('day', rs.created_at)::date)
        rs.repo_id,
        rs.findings,
        date_trunc('day', rs.created_at)::date AS scan_day
    FROM run_secrets rs
    JOIN repos r ON r.id = rs.repo_id
    LEFT JOIN provider_instances pi ON pi.id = r.provider_instance_id
    WHERE rs.repo_id IS NOT NULL AND rs.repo_id <> ''
      AND (pi.id IS NULL OR pi.enabled = true)
      AND rs.created_at >= NOW() - (?::int || ' days')::interval
      -- Only include repos that have at least one scan in the
      -- visible 30-day window so we don't surface inventory that's
      -- effectively stale (matches the earlier repos CTE).
      AND EXISTS (
          SELECT 1 FROM run_secrets rs2
          WHERE rs2.repo_id = rs.repo_id
            AND rs2.created_at >= date_trunc('day', NOW()) - INTERVAL '30 days'
      )
    ORDER BY rs.repo_id, date_trunc('day', rs.created_at)::date, rs.created_at DESC
) lpd
CROSS JOIN LATERAL jsonb_array_elements(COALESCE(lpd.findings, '[]'::jsonb)) AS finding
WHERE lpd.findings IS NOT NULL`

	type scanRow struct {
		RepoID     string `gorm:"column:repo_id"`
		ScanDay    string `gorm:"column:scan_day"`
		SecretType string `gorm:"column:secret_type"`
		Match      string `gorm:"column:match"`
		Secret     string `gorm:"column:secret"`
		DedupeKey  string `gorm:"column:dedupe_key"`
	}
	var scanRows []scanRow
	if err := db.WithContext(ctx).Raw(query, lookbackDays).Scan(&scanRows).Error; err != nil {
		return nil, err
	}

	type finding struct {
		Date       string
		SecretType string
		Match      string
		Secret     string
	}

	// Forward-fill in Go. For each repo, sort the scan days; for each
	// day in the visible 30-day window, pick the latest scan_day ≤
	// that day and project its findings onto that day. Dedup
	// across repos within a day by dedupe_key so a secret leak that
	// appears in multiple repos is counted once per day (mirrors the
	// original SQL's DISTINCT on the deduped_findings CTE).
	type scanFinding struct {
		SecretType string
		Match      string
		Secret     string
		DedupeKey  string
	}
	type scanKey struct {
		RepoID  string
		ScanDay time.Time
	}
	perScan := make(map[scanKey][]scanFinding, len(scanRows))
	repoDays := make(map[string][]time.Time, 256)
	seenScanKey := make(map[scanKey]struct{}, len(scanRows))
	for _, sr := range scanRows {
		day, err := time.Parse("2006-01-02", sr.ScanDay)
		if err != nil {
			continue
		}
		key := scanKey{RepoID: sr.RepoID, ScanDay: day}
		perScan[key] = append(perScan[key], scanFinding{
			SecretType: sr.SecretType,
			Match:      sr.Match,
			Secret:     sr.Secret,
			DedupeKey:  sr.DedupeKey,
		})
		if _, dup := seenScanKey[key]; !dup {
			seenScanKey[key] = struct{}{}
			repoDays[sr.RepoID] = append(repoDays[sr.RepoID], day)
		}
	}
	for repo := range repoDays {
		days := repoDays[repo]
		sort.Slice(days, func(i, j int) bool { return days[i].Before(days[j]) })
		repoDays[repo] = days
	}

	// Build the 30-day window inclusive of today, matching the
	// original generate_series(NOW() - 30 days, NOW(), 1 day) shape.
	today := time.Now().UTC().Truncate(24 * time.Hour)
	const windowDays = 31
	window := make([]time.Time, windowDays)
	for i := 0; i < windowDays; i++ {
		window[i] = today.AddDate(0, 0, -(windowDays - 1 - i))
	}

	findings := make([]finding, 0, len(scanRows))
	for _, day := range window {
		dateStr := day.Format("2006-01-02")
		seen := make(map[string]struct{}, 128)
		for repo, scans := range repoDays {
			// Latest scan_day ≤ day via binary search.
			idx := sort.Search(len(scans), func(i int) bool { return scans[i].After(day) }) - 1
			if idx < 0 {
				continue
			}
			for _, sf := range perScan[scanKey{RepoID: repo, ScanDay: scans[idx]}] {
				if _, dup := seen[sf.DedupeKey]; dup {
					continue
				}
				seen[sf.DedupeKey] = struct{}{}
				findings = append(findings, finding{
					Date:       dateStr,
					SecretType: sf.SecretType,
					Match:      sf.Match,
					Secret:     sf.Secret,
				})
			}
		}
	}

	// Compute hashes and look up dismissed secrets (with timestamps).
	hashes := make([]string, len(findings))
	hashSet := map[string]bool{}
	for i, f := range findings {
		s := secretprobe.ExtractSecret(f.Match)
		if f.Secret != "" {
			s = secretprobe.ExtractSecret(f.Secret)
		}
		h := secretprobe.SecretHash(s)
		hashes[i] = h
		hashSet[h] = true
	}
	dismissedAt := map[string]time.Time{}
	if len(hashSet) > 0 {
		uniqueHashes := make([]string, 0, len(hashSet))
		for h := range hashSet {
			uniqueHashes = append(uniqueHashes, h)
		}
		var dismissals []secretprobe.SecretDismissal
		db.WithContext(ctx).
			Where("secret_hash IN ?", uniqueHashes).
			Find(&dismissals)
		for _, d := range dismissals {
			dismissedAt[d.SecretHash] = d.DismissedAt
		}
	}

	// Aggregate counts per day+type, excluding secrets dismissed on or before that day.
	type dayType struct {
		date       string
		secretType string
	}
	counts := map[dayType]int64{}
	globalTypeCounts := map[string]int64{}
	for i, f := range findings {
		if t, ok := dismissedAt[hashes[i]]; ok {
			// Parse the finding's day and skip if dismissed on or before that day.
			dismissDay := t.Truncate(24 * time.Hour)
			if day, err := time.Parse("2006-01-02", f.Date); err == nil && !day.Before(dismissDay) {
				continue
			}
		}
		key := dayType{date: f.Date, secretType: f.SecretType}
		counts[key]++
		globalTypeCounts[f.SecretType]++
	}

	// Determine top-5 types globally.
	type ranked struct {
		secretType string
		count      int64
	}
	var sorted []ranked
	for st, c := range globalTypeCounts {
		sorted = append(sorted, ranked{st, c})
	}
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].count != sorted[j].count {
			return sorted[i].count > sorted[j].count
		}
		return sorted[i].secretType < sorted[j].secretType
	})
	topTypes := map[string]bool{}
	for i, r := range sorted {
		if i >= 5 {
			break
		}
		topTypes[r.secretType] = true
	}

	// Build final rows, collapsing non-top types into "other".
	merged := map[dayType]int64{}
	for key, cnt := range counts {
		effectiveType := key.secretType
		if !topTypes[effectiveType] {
			effectiveType = "other"
		}
		merged[dayType{date: key.date, secretType: effectiveType}] += cnt
	}

	rows := make([]SecretTrendRow, 0, len(merged))
	for key, cnt := range merged {
		rows = append(rows, SecretTrendRow{Date: key.date, SecretType: key.secretType, Count: cnt})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Date != rows[j].Date {
			return rows[i].Date < rows[j].Date
		}
		return rows[i].Count > rows[j].Count
	})
	if rows == nil {
		rows = []SecretTrendRow{}
	}
	return rows, nil
}

// SecretsDashboardStatsResponse is the combined response for /api/secrets/stats.
type SecretsDashboardStatsResponse struct {
	Distribution []SecretDistributionRow `json:"distribution"`
	Probe        ProbeStatsResponse      `json:"probe"`
}

// SecretsDashboardStatsHandler returns distribution + probe stats in one response.
//
// GET /api/secrets/stats
func SecretsDashboardStatsHandler(db *gorm.DB, authService *auth.Service, c cache.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if requireAuth(w, r, authService) == nil {
			return
		}

		watermark := secretsStatsWatermark(r.Context(), db)

		if entry, ok, _ := cache.GetJSON[secretsCacheEntry[SecretsDashboardStatsResponse]](r.Context(), c, secretsStatsCacheKey); ok {
			if !watermark.IsZero() && !entry.Watermark.Before(watermark) {
				writeJSON(w, http.StatusOK, entry.Response)
				return
			}
			writeJSON(w, http.StatusOK, entry.Response)
			go func() {
				if !secretsStatsRefreshing.CompareAndSwap(false, true) {
					return
				}
				defer secretsStatsRefreshing.Store(false)
				ctx := context.Background()
				resp, err := computeSecretsDashboardStats(ctx, db)
				if err != nil {
					log.Printf("secrets stats background refresh: %v", err)
					return
				}
				_ = maybeStoreSecretsCache(ctx, c, secretsStatsCacheKey, watermark, resp)
			}()
			return
		}

		resp, err := computeSecretsDashboardStats(r.Context(), db)
		if err != nil {
			http.Error(w, "failed to load secrets stats", http.StatusInternalServerError)
			return
		}
		_ = maybeStoreSecretsCache(r.Context(), c, secretsStatsCacheKey, watermark, resp)
		writeJSON(w, http.StatusOK, resp)
	}
}

func computeSecretsDashboardStats(ctx context.Context, db *gorm.DB) (SecretsDashboardStatsResponse, error) {
	dist, err := computeSecretsDistribution(ctx, db)
	if err != nil {
		return SecretsDashboardStatsResponse{}, err
	}
	probe, err := computeProbeStats(ctx, db)
	if err != nil {
		return SecretsDashboardStatsResponse{}, err
	}
	return SecretsDashboardStatsResponse{
		Distribution: dist,
		Probe:        probe,
	}, nil
}

// secretsStatsWatermark returns the latest of the run_secrets and secret_probes
// watermarks so the cache invalidates when either data source changes.
func secretsStatsWatermark(ctx context.Context, db *gorm.DB) time.Time {
	w1 := secretsWatermark(ctx, db)
	w2 := probeStatsWatermark(ctx, db)
	if w2.After(w1) {
		return w2
	}
	return w1
}

func computeSecretsDistribution(ctx context.Context, db *gorm.DB) ([]SecretDistributionRow, error) {
	query := `
WITH latest_repo_secrets AS (
  SELECT DISTINCT ON (rs.repo_id)
    rs.repo_id,
    rs.findings
  FROM run_secrets rs
  JOIN repos r ON r.id = rs.repo_id
  LEFT JOIN provider_instances pi ON pi.id = r.provider_instance_id
  WHERE rs.repo_id IS NOT NULL AND rs.repo_id <> ''
    AND (pi.id IS NULL OR pi.enabled = true)
  ORDER BY rs.repo_id, rs.created_at DESC
),
deduped_findings AS (
  SELECT DISTINCT
    COALESCE(finding->>'RuleID', 'unknown') AS secret_type,
    COALESCE(finding->>'Match', '') AS match,
    COALESCE(finding->>'Secret', '') AS secret,
    COALESCE(
      NULLIF(finding->>'Fingerprint', ''),
      md5(
        concat_ws(
          '|',
          COALESCE(finding->>'RuleID', ''),
          COALESCE(finding->>'Description', ''),
          COALESCE(finding->>'File', ''),
          COALESCE(finding->>'StartLine', ''),
          COALESCE(finding->>'Match', ''),
          COALESCE(finding->>'Secret', '')
        )
      )
    ) AS dedupe_key
  FROM latest_repo_secrets rs
  CROSS JOIN LATERAL jsonb_array_elements(COALESCE(rs.findings, '[]'::jsonb)) AS finding
)
SELECT secret_type, match, secret FROM deduped_findings`

	var findings []struct {
		SecretType string `gorm:"column:secret_type"`
		Match      string `gorm:"column:match"`
		Secret     string `gorm:"column:secret"`
	}
	if err := db.WithContext(ctx).Raw(query).Scan(&findings).Error; err != nil {
		return nil, err
	}

	// Compute hashes and look up dismissed secrets.
	hashes := make([]string, len(findings))
	for i, f := range findings {
		s := secretprobe.ExtractSecret(f.Match)
		if f.Secret != "" {
			s = secretprobe.ExtractSecret(f.Secret)
		}
		hashes[i] = secretprobe.SecretHash(s)
	}
	dismissed := map[string]bool{}
	if len(hashes) > 0 {
		var dismissedHashes []string
		db.WithContext(ctx).
			Model(&secretprobe.SecretDismissal{}).
			Where("secret_hash IN ?", hashes).
			Pluck("secret_hash", &dismissedHashes)
		for _, h := range dismissedHashes {
			dismissed[h] = true
		}
	}

	// Aggregate counts excluding dismissed, then rank top 6 + other.
	counts := map[string]int64{}
	for i, f := range findings {
		if dismissed[hashes[i]] {
			continue
		}
		counts[f.SecretType]++
	}

	type ranked struct {
		secretType string
		count      int64
	}
	var sorted []ranked
	for st, c := range counts {
		sorted = append(sorted, ranked{st, c})
	}
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].count != sorted[j].count {
			return sorted[i].count > sorted[j].count
		}
		return sorted[i].secretType < sorted[j].secretType
	})

	rows := []SecretDistributionRow{}
	var otherCount int64
	for i, r := range sorted {
		if i < 6 {
			rows = append(rows, SecretDistributionRow{SecretType: r.secretType, FindingCount: r.count})
		} else {
			otherCount += r.count
		}
	}
	if otherCount > 0 {
		rows = append(rows, SecretDistributionRow{SecretType: "other", FindingCount: otherCount})
	}
	return rows, nil
}

// maybeStoreSecretsCache stores a secrets dashboard response in the cache,
// respecting the Cache-Control: no-store header.
func maybeStoreSecretsCache[T any](ctx context.Context, c cache.Store, key string, watermark time.Time, response T) error {
	if !cache.ShouldStore(ctx) {
		return nil
	}
	return cache.SetJSON(ctx, c, key, secretsCacheEntry[T]{
		Watermark: watermark,
		Response:  response,
	}, secretsCacheTTL)
}

// ProbeStatsResponse is the cached view of secret probe statistics.
type ProbeStatsResponse struct {
	Total         int64 `json:"total"`
	Valid         int64 `json:"valid"`
	Invalid       int64 `json:"invalid"`
	Revoked       int64 `json:"revoked"`
	Expired       int64 `json:"expired"`
	FalsePositive int64 `json:"false_positive"`
	Unknown       int64 `json:"unknown"`
	Error         int64 `json:"error"`
}

// probeStatsWatermark returns the latest probed_at timestamp from secret_probes.
func probeStatsWatermark(ctx context.Context, db *gorm.DB) time.Time {
	var t time.Time
	db.WithContext(ctx).Raw(
		"SELECT COALESCE(MAX(probed_at), TIMESTAMPTZ 'epoch') FROM secret_probes",
	).Scan(&t)
	return t
}

func computeProbeStats(ctx context.Context, db *gorm.DB) (ProbeStatsResponse, error) {
	counts, total, err := secretprobe.Stats(ctx, db)
	if err != nil {
		return ProbeStatsResponse{}, err
	}
	return ProbeStatsResponse{
		Total:         total,
		Valid:         counts[secretprobe.StatusValid],
		Invalid:       counts[secretprobe.StatusInvalid],
		Revoked:       counts[secretprobe.StatusRevoked],
		Expired:       counts[secretprobe.StatusExpired],
		FalsePositive: counts[secretprobe.StatusFalsePositive],
		Unknown:       counts[secretprobe.StatusUnknown],
		Error:         counts[secretprobe.StatusError],
	}, nil
}

// SecretFindingRow is a single deduplicated finding returned for the drawer.
type SecretFindingRow struct {
	RuleID          string  `json:"rule_id"`
	EffectiveRuleID string  `json:"effective_rule_id,omitempty"`
	Description     string  `json:"description"`
	File            string  `json:"file"`
	StartLine       int     `json:"start_line"`
	Match           string  `json:"match"`
	Secret          string  `json:"secret,omitempty"`
	Entropy         float64 `json:"entropy,omitempty"`
	SubType         string  `json:"sub_type,omitempty"`
	ProbeStatus     string  `json:"probe_status,omitempty"`
	ProbeReason     string  `json:"probe_reason,omitempty"`
	Dismissed       bool    `json:"dismissed"`
	SecretHash      string  `json:"secret_hash,omitempty"`
}

// SecretFindingsPage wraps paginated findings with a total count.
type SecretFindingsPage struct {
	Items []SecretFindingRow `json:"items"`
	Total int64              `json:"total"`
}

// SecretsFindingsHandler returns deduplicated individual findings for a given
// repo, sourced from the latest run only. Supports pagination via limit/offset.
//
// GET /api/secrets/findings?repo_id=...&limit=100&offset=0
func SecretsFindingsHandler(db *gorm.DB, authService *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if requireAuth(w, r, authService) == nil {
			return
		}

		repoID := r.URL.Query().Get("repo_id")
		if repoID == "" {
			http.Error(w, "repo_id is required", http.StatusBadRequest)
			return
		}

		limit := 100
		offset := 0
		if v := r.URL.Query().Get("limit"); v != "" {
			if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 500 {
				limit = n
			}
		}
		if v := r.URL.Query().Get("offset"); v != "" {
			if n, err := strconv.Atoi(v); err == nil && n >= 0 {
				offset = n
			}
		}

		const cte = `
WITH latest AS (
  SELECT findings
  FROM run_secrets
  WHERE repo_id = @repo_id
  ORDER BY created_at DESC
  LIMIT 1
),
exploded AS (
  SELECT DISTINCT
    COALESCE(finding->>'RuleID', 'unknown')   AS rule_id,
    COALESCE(finding->>'Description', '')     AS description,
    COALESCE(finding->>'File', '')            AS file,
    COALESCE((finding->>'StartLine')::int, 0) AS start_line,
    COALESCE(finding->>'Match', '')           AS match,
    COALESCE(finding->>'Secret', '')          AS secret,
    COALESCE((finding->>'Entropy')::float, 0) AS entropy,
    COALESCE(
      NULLIF(finding->>'Fingerprint', ''),
      md5(concat_ws('|',
        COALESCE(finding->>'RuleID', ''),
        COALESCE(finding->>'Description', ''),
        COALESCE(finding->>'File', ''),
        COALESCE(finding->>'StartLine', ''),
        COALESCE(finding->>'Match', ''),
        COALESCE(finding->>'Secret', '')
      ))
    ) AS dedupe_key
  FROM latest
  CROSS JOIN LATERAL jsonb_array_elements(COALESCE(findings, '[]'::jsonb)) AS finding
),
deduped AS (
  SELECT DISTINCT ON (dedupe_key) rule_id, description, file, start_line, match, secret, entropy
  FROM exploded
  ORDER BY dedupe_key, rule_id, file, start_line
)`

		var total int64
		countQuery := cte + "\nSELECT COUNT(*) FROM deduped"
		if err := db.WithContext(r.Context()).Raw(countQuery, map[string]interface{}{"repo_id": repoID}).Scan(&total).Error; err != nil {
			http.Error(w, "failed to count secret findings", http.StatusInternalServerError)
			return
		}

		dataQuery := cte + "\nSELECT rule_id, description, file, start_line, match, secret, entropy FROM deduped ORDER BY rule_id, file, start_line LIMIT @limit OFFSET @offset"
		var rows []SecretFindingRow
		if err := db.WithContext(r.Context()).Raw(dataQuery, map[string]interface{}{
			"repo_id": repoID,
			"limit":   limit,
			"offset":  offset,
		}).Scan(&rows).Error; err != nil {
			http.Error(w, "failed to load secret findings", http.StatusInternalServerError)
			return
		}
		if rows == nil {
			rows = []SecretFindingRow{}
		}

		// Classify all findings concurrently and compute secret hashes.
		type classResult struct {
			index    int
			subType  string
			hash     string
			classify secretprobe.Classification
		}
		results := make([]classResult, len(rows))
		var wg sync.WaitGroup
		sem := make(chan struct{}, 64)
		for i := range rows {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()

				row := &rows[i]
				secret := secretprobe.ExtractSecret(row.Match)
				if row.Secret != "" {
					secret = secretprobe.ExtractSecret(row.Secret)
				}
				results[i] = classResult{
					index:    i,
					subType:  secretprobe.ExtractKeyName(row.Match),
					hash:     secretprobe.SecretHash(secret),
					classify: secretprobe.Classify(secret, row.RuleID),
				}
			}(i)
		}
		wg.Wait()

		// Collect hashes to check for dismissals.
		hashes := make([]string, len(results))
		for i, cr := range results {
			hashes[i] = cr.hash
		}

		// Look up dismissed hashes.
		dismissed := map[string]bool{}
		if len(hashes) > 0 {
			var dismissedHashes []string
			db.WithContext(r.Context()).
				Model(&secretprobe.SecretDismissal{}).
				Where("secret_hash IN ?", hashes).
				Pluck("secret_hash", &dismissedHashes)
			for _, h := range dismissedHashes {
				dismissed[h] = true
			}
		}

		// Apply results to rows.
		for _, cr := range results {
			row := &rows[cr.index]
			row.SubType = cr.subType
			row.SecretHash = cr.hash
			row.ProbeStatus = string(cr.classify.ProbeOutput.Status)
			row.ProbeReason = cr.classify.ProbeOutput.Reason
			if cr.classify.Reclassified {
				row.EffectiveRuleID = cr.classify.EffectiveRuleID
			}
			row.Dismissed = dismissed[cr.hash]
		}

		writeJSON(w, http.StatusOK, SecretFindingsPage{Items: rows, Total: total})
	}
}

// SecretDismissHandler toggles the dismissed state of a secret finding.
//
// POST /api/secrets/dismiss
// Body: {"secret_hash": "...", "dismiss": true}
func SecretDismissHandler(db *gorm.DB, authService *auth.Service, c cache.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := requireAuth(w, r, authService)
		if user == nil {
			return
		}

		var body struct {
			SecretHash string `json:"secret_hash"`
			Dismiss    bool   `json:"dismiss"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.SecretHash == "" {
			http.Error(w, "secret_hash is required", http.StatusBadRequest)
			return
		}

		if body.Dismiss {
			d := secretprobe.SecretDismissal{
				SecretHash:  body.SecretHash,
				DismissedBy: user.Email,
				DismissedAt: time.Now(),
			}
			db.WithContext(r.Context()).
				Where("secret_hash = ?", body.SecretHash).
				FirstOrCreate(&d)
		} else {
			db.WithContext(r.Context()).
				Where("secret_hash = ?", body.SecretHash).
				Delete(&secretprobe.SecretDismissal{})
		}

		// Invalidate secrets dashboard caches so trend/table/distribution reflect the change.
		_ = cache.Delete(r.Context(), c, secretsTableCacheKey)
		_ = cache.Delete(r.Context(), c, secretsTrendCacheKey)
		_ = cache.Delete(r.Context(), c, secretsStatsCacheKey)

		writeJSON(w, http.StatusOK, map[string]bool{"dismissed": body.Dismiss})
	}
}
