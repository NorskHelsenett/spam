package uiapi

import (
	"net/http"
	"time"

	"github.com/NorskHelsenett/spam/internal/auth"
	"gorm.io/gorm"
)

// SecretTableRow represents a row in the secrets datatable.
type SecretTableRow struct {
	Repo               string    `json:"repo"`
	RepoID             string    `json:"repo_id"`
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
  df.secret_type,
  COUNT(*) AS unique_finding_count,
  MAX(df.last_scanned) AS last_scanned
FROM deduped_findings df
JOIN repos r
  ON r.id = df.repo_id
LEFT JOIN provider_instances pi
  ON pi.id = r.provider_instance_id
GROUP BY repo, r.id, df.secret_type
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
WITH latest_run_per_repo_per_day AS (
  SELECT DISTINCT ON (repo_id, date_trunc('day', created_at))
    repo_id,
    findings,
    date_trunc('day', created_at)::date AS day
  FROM run_secrets
  WHERE repo_id IS NOT NULL AND repo_id <> ''
    AND created_at >= NOW() - INTERVAL '30 days'
  ORDER BY repo_id, date_trunc('day', created_at), created_at DESC
),
deduped_findings AS (
  SELECT DISTINCT
    lrs.day,
    COALESCE(finding->>'RuleID', 'unknown') AS secret_type,
    lrs.repo_id,
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
  FROM latest_run_per_repo_per_day lrs
  CROSS JOIN LATERAL jsonb_array_elements(COALESCE(lrs.findings, '[]'::jsonb)) AS finding
),
top_types AS (
  SELECT secret_type
  FROM deduped_findings
  GROUP BY secret_type
  ORDER BY COUNT(*) DESC
  LIMIT 5
),
daily AS (
  SELECT
    day,
    secret_type,
    COUNT(*) AS cnt
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

// SecretsFindingsHandler returns deduplicated individual findings for a given
// repo + secret type, sourced from the latest run only.
//
// GET /api/secrets/findings?repo_id=...&secret_type=...
func SecretsFindingsHandler(db *gorm.DB, authService *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if requireAuth(w, r, authService) == nil {
			return
		}

		repoID := r.URL.Query().Get("repo_id")
		secretType := r.URL.Query().Get("secret_type")
		if repoID == "" || secretType == "" {
			http.Error(w, "repo_id and secret_type are required", http.StatusBadRequest)
			return
		}

		query := `
WITH latest AS (
  SELECT findings
  FROM run_secrets
  WHERE repo_id = ?
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
  WHERE COALESCE(finding->>'RuleID', 'unknown') = ?
)
SELECT DISTINCT ON (dedupe_key) rule_id, description, file, start_line, match
FROM exploded
ORDER BY dedupe_key, file, start_line`

		var rows []SecretFindingRow
		if err := db.WithContext(r.Context()).Raw(query, repoID, secretType).Scan(&rows).Error; err != nil {
			http.Error(w, "failed to load secret findings", http.StatusInternalServerError)
			return
		}
		if rows == nil {
			rows = []SecretFindingRow{}
		}
		writeJSON(w, http.StatusOK, rows)
	}
}
