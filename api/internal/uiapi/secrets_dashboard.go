package uiapi

import (
	"net/http"

	"github.com/NorskHelsenett/spam/internal/auth"
	"gorm.io/gorm"
)

// SecretTableRow represents a row in the secrets datatable.
type SecretTableRow struct {
	Repo               string `json:"repo"`
	SecretType         string `json:"secret_type"`
	UniqueFindingCount int64  `json:"unique_finding_count"`
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
    rs.findings
  FROM run_secrets rs
  WHERE rs.repo_id IS NOT NULL
    AND rs.repo_id <> ''
  ORDER BY rs.repo_id, rs.created_at DESC
),
deduped_findings AS (
  SELECT DISTINCT
    lrs.repo_id,
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
  df.secret_type,
  COUNT(*) AS unique_finding_count
FROM deduped_findings df
JOIN repos r
  ON r.id = df.repo_id
LEFT JOIN provider_instances pi
  ON pi.id = r.provider_instance_id
GROUP BY repo, df.secret_type
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
WITH top_types AS (
  SELECT COALESCE(finding->>'RuleID', 'unknown') AS secret_type
  FROM run_secrets
  CROSS JOIN LATERAL jsonb_array_elements(COALESCE(findings, '[]'::jsonb)) AS finding
  WHERE created_at >= NOW() - INTERVAL '30 days'
  GROUP BY secret_type
  ORDER BY COUNT(*) DESC
  LIMIT 5
),
daily AS (
  SELECT
    date_trunc('day', rs.created_at)::date AS day,
    COALESCE(finding->>'RuleID', 'unknown') AS secret_type,
    COUNT(*) AS cnt
  FROM run_secrets rs
  CROSS JOIN LATERAL jsonb_array_elements(COALESCE(rs.findings, '[]'::jsonb)) AS finding
  WHERE rs.created_at >= NOW() - INTERVAL '30 days'
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
)
SELECT
  COALESCE(finding->>'RuleID', 'unknown') AS secret_type,
  COUNT(*) AS finding_count
FROM latest_repo_secrets rs
CROSS JOIN LATERAL jsonb_array_elements(COALESCE(rs.findings, '[]'::jsonb)) AS finding
GROUP BY COALESCE(finding->>'RuleID', 'unknown')
ORDER BY finding_count DESC, secret_type ASC`

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
