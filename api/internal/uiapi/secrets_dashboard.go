package uiapi

import (
	"net/http"
	"strconv"
	"time"

	"github.com/NorskHelsenett/spam/internal/auth"
	"gorm.io/gorm"
)

// SecretTableRow represents a row in the secrets datatable.
type SecretTableRow struct {
	Repo               string    `json:"repo"`
	RepoID             string    `json:"repo_id"`
	Provider           string    `json:"provider"`
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
func SecretsDashboardTableHandler(db *gorm.DB, authService *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if requireAuth(w, r, authService) == nil {
			return
		}

		query := `
WITH latest_repo_secrets AS (
  SELECT DISTINCT ON (rs.repo_id)
    rs.repo_id,
    rs.findings,
    rs.created_at
  FROM run_secrets rs
  WHERE rs.repo_id IS NOT NULL
    AND rs.repo_id <> ''
  ORDER BY rs.repo_id, rs.created_at DESC
),
deduped_findings AS (
  SELECT DISTINCT
    lrs.repo_id,
    lrs.created_at AS last_scanned,
    COALESCE(finding->>'RuleID', 'unknown') AS secret_type,
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
  df.secret_type,
  COUNT(*) AS unique_finding_count,
  MAX(df.last_scanned) AS last_scanned
FROM deduped_findings df
JOIN repos r
  ON r.id = df.repo_id
LEFT JOIN provider_instances pi
  ON pi.id = r.provider_instance_id
GROUP BY repo, r.id, r.provider, df.secret_type
ORDER BY repo ASC, df.secret_type ASC`

		var rows []SecretTableRow
		if err := db.WithContext(r.Context()).Raw(query).Scan(&rows).Error; err != nil {
			http.Error(w, "failed to load secrets table", http.StatusInternalServerError)
			return
		}
		if rows == nil {
			rows = []SecretTableRow{}
		}
		writeJSON(w, http.StatusOK, rows)
	}
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
func SecretsDashboardTrendHandler(db *gorm.DB, authService *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if requireAuth(w, r, authService) == nil {
			return
		}

		query := `
WITH date_series AS (
  SELECT generate_series(
    date_trunc('day', NOW() - INTERVAL '30 days')::date,
    date_trunc('day', NOW() - INTERVAL '1 day')::date,
    '1 day'::interval
  )::date AS day
),
all_repo_scans AS (
  -- Latest scan per repo per day (all time, needed for carry-forward)
  SELECT DISTINCT ON (repo_id, date_trunc('day', created_at)::date)
    repo_id,
    findings,
    date_trunc('day', created_at)::date AS scan_day
  FROM run_secrets
  WHERE repo_id IS NOT NULL AND repo_id <> ''
    AND created_at < date_trunc('day', NOW())
  ORDER BY repo_id, date_trunc('day', created_at)::date, created_at DESC
),
repos AS (
  -- Only repos with at least one scan within the 30-day window
  SELECT DISTINCT repo_id FROM all_repo_scans
  WHERE scan_day >= date_trunc('day', NOW()) - INTERVAL '30 days'
),
filled AS (
  -- For each repo+day, carry forward the most recent scan on or before that day
  SELECT DISTINCT ON (r.repo_id, ds.day)
    r.repo_id,
    ds.day,
    ars.findings
  FROM repos r
  CROSS JOIN date_series ds
  JOIN all_repo_scans ars ON ars.repo_id = r.repo_id AND ars.scan_day <= ds.day
  ORDER BY r.repo_id, ds.day, ars.scan_day DESC
),
deduped_findings AS (
  SELECT DISTINCT
    f.day,
    COALESCE(finding->>'RuleID', 'unknown') AS secret_type,
    f.repo_id,
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
  FROM filled f
  CROSS JOIN LATERAL jsonb_array_elements(COALESCE(f.findings, '[]'::jsonb)) AS finding
),
top_types AS (
  SELECT secret_type
  FROM deduped_findings
  GROUP BY secret_type
  ORDER BY COUNT(*) DESC
  LIMIT 5
),
daily AS (
  SELECT day, secret_type, COUNT(*) AS cnt
  FROM deduped_findings
  GROUP BY day, secret_type
)
SELECT
  d.day::text AS date,
  CASE WHEN tt.secret_type IS NOT NULL THEN d.secret_type ELSE 'other' END AS secret_type,
  SUM(d.cnt) AS count
FROM daily d
LEFT JOIN top_types tt ON tt.secret_type = d.secret_type
GROUP BY d.day, CASE WHEN tt.secret_type IS NOT NULL THEN d.secret_type ELSE 'other' END
ORDER BY d.day ASC, count DESC`

		var rows []SecretTrendRow
		if err := db.WithContext(r.Context()).Raw(query).Scan(&rows).Error; err != nil {
			http.Error(w, "failed to load secrets trend", http.StatusInternalServerError)
			return
		}
		if rows == nil {
			rows = []SecretTrendRow{}
		}
		writeJSON(w, http.StatusOK, rows)
	}
}

// SecretsDashboardDistributionHandler returns secret type counts for the donut chart.
//
// GET /api/secrets/distribution
func SecretsDashboardDistributionHandler(db *gorm.DB, authService *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if requireAuth(w, r, authService) == nil {
			return
		}

		query := `
WITH latest_repo_secrets AS (
  SELECT DISTINCT ON (repo_id)
    repo_id,
    findings
  FROM run_secrets
  WHERE repo_id IS NOT NULL AND repo_id <> ''
  ORDER BY repo_id, created_at DESC
),
deduped_findings AS (
  SELECT DISTINCT
    COALESCE(finding->>'RuleID', 'unknown') AS secret_type,
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
),
counts AS (
  SELECT
    secret_type,
    COUNT(*) AS finding_count
  FROM deduped_findings
  GROUP BY secret_type
),
ranked AS (
  SELECT
    secret_type,
    finding_count,
    ROW_NUMBER() OVER (ORDER BY finding_count DESC, secret_type ASC) AS rn
  FROM counts
)
SELECT
  CASE WHEN rn <= 6 THEN secret_type ELSE 'other' END AS secret_type,
  SUM(finding_count) AS finding_count
FROM ranked
GROUP BY CASE WHEN rn <= 6 THEN secret_type ELSE 'other' END
ORDER BY
  CASE WHEN (CASE WHEN rn <= 6 THEN secret_type ELSE 'other' END) = 'other' THEN 1 ELSE 0 END,
  SUM(finding_count) DESC`

		var rows []SecretDistributionRow
		if err := db.WithContext(r.Context()).Raw(query).Scan(&rows).Error; err != nil {
			http.Error(w, "failed to load secrets distribution", http.StatusInternalServerError)
			return
		}
		if rows == nil {
			rows = []SecretDistributionRow{}
		}
		writeJSON(w, http.StatusOK, rows)
	}
}

// SecretFindingRow is a single deduplicated finding returned for the drawer.
type SecretFindingRow struct {
	RuleID      string `json:"rule_id"`
	Description string `json:"description"`
	File        string `json:"file"`
	StartLine   int    `json:"start_line"`
	Match       string `json:"match"`
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
  SELECT DISTINCT ON (dedupe_key) rule_id, description, file, start_line, match
  FROM exploded
  ORDER BY dedupe_key, rule_id, file, start_line
)`

		var total int64
		countQuery := cte + "\nSELECT COUNT(*) FROM deduped"
		if err := db.WithContext(r.Context()).Raw(countQuery, map[string]interface{}{"repo_id": repoID}).Scan(&total).Error; err != nil {
			http.Error(w, "failed to count secret findings", http.StatusInternalServerError)
			return
		}

		dataQuery := cte + "\nSELECT rule_id, description, file, start_line, match FROM deduped ORDER BY rule_id, file, start_line LIMIT @limit OFFSET @offset"
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
		writeJSON(w, http.StatusOK, SecretFindingsPage{Items: rows, Total: total})
	}
}
