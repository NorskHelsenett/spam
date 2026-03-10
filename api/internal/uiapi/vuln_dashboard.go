package uiapi

import (
	"net/http"
	"strconv"
	"time"

	"github.com/NorskHelsenett/spam/internal/auth"
	"gorm.io/gorm"
)

// VulnSummaryHandler returns overall vulnerability counts and last scan time.
//
// GET /api/vuln/summary
func VulnSummaryHandler(db *gorm.DB, authService *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if requireAuth(w, r, authService) == nil {
			return
		}

		var summary struct {
			TotalCritical int        `json:"total_critical"`
			TotalHigh     int        `json:"total_high"`
			TotalMedium   int        `json:"total_medium"`
			TotalLow      int        `json:"total_low"`
			TotalUnknown  int        `json:"total_unknown"`
			TotalVulns    int        `json:"total_vulns"`
			ScannedSBOMs  int        `json:"scanned_sboms"`
			LastScannedAt *time.Time `json:"last_scanned_at"`
		}

		type row struct {
			TotalCritical int
			TotalHigh     int
			TotalMedium   int
			TotalLow      int
			TotalUnknown  int
			ScannedSBOMs  int
			LastScannedAt *time.Time
		}
		var r2 row
		db.WithContext(r.Context()).Raw(`
			SELECT
				COALESCE(SUM(critical_count), 0) AS total_critical,
				COALESCE(SUM(high_count), 0)     AS total_high,
				COALESCE(SUM(medium_count), 0)   AS total_medium,
				COALESCE(SUM(low_count), 0)      AS total_low,
				COALESCE(SUM(unknown_count), 0)  AS total_unknown,
				COUNT(*)                          AS scanned_sb_oms,
				MAX(scanned_at)                  AS last_scanned_at
			FROM trivy_scan_results
		`).Scan(&r2)

		summary.TotalCritical = r2.TotalCritical
		summary.TotalHigh = r2.TotalHigh
		summary.TotalMedium = r2.TotalMedium
		summary.TotalLow = r2.TotalLow
		summary.TotalUnknown = r2.TotalUnknown
		summary.ScannedSBOMs = r2.ScannedSBOMs
		summary.LastScannedAt = r2.LastScannedAt
		summary.TotalVulns = r2.TotalCritical + r2.TotalHigh + r2.TotalMedium + r2.TotalLow + r2.TotalUnknown

		writeJSON(w, http.StatusOK, summary)
	}
}

// VulnReposHandler returns per-repo vulnerability counts sorted by severity.
//
// GET /api/vuln/repos
func VulnReposHandler(db *gorm.DB, authService *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if requireAuth(w, r, authService) == nil {
			return
		}

		type repoRow struct {
			RepoID        string     `json:"repo_id"`
			RepoSlug      string     `json:"repo_slug"`
			CriticalCount int        `json:"critical_count"`
			HighCount     int        `json:"high_count"`
			MediumCount   int        `json:"medium_count"`
			LowCount      int        `json:"low_count"`
			UnknownCount  int        `json:"unknown_count"`
			LastScannedAt *time.Time `json:"last_scanned_at"`
		}

		var rows []repoRow
		db.WithContext(r.Context()).Raw(`
			SELECT
				tsr.repo_id,
				COALESCE(repo.org || '/' || repo.slug, tsr.repo_id) AS repo_slug,
				SUM(tsr.critical_count) AS critical_count,
				SUM(tsr.high_count)     AS high_count,
				SUM(tsr.medium_count)   AS medium_count,
				SUM(tsr.low_count)      AS low_count,
				SUM(tsr.unknown_count)  AS unknown_count,
				MAX(tsr.scanned_at)     AS last_scanned_at
			FROM trivy_scan_results tsr
			LEFT JOIN repos repo ON repo.id = tsr.repo_id
			GROUP BY tsr.repo_id, repo.org, repo.slug
			ORDER BY critical_count DESC, high_count DESC, medium_count DESC
		`).Scan(&rows)

		if rows == nil {
			rows = []repoRow{}
		}

		writeJSON(w, http.StatusOK, rows)
	}
}

// VulnListHandler returns individual vulnerabilities extracted from Trivy raw JSON.
//
// GET /api/vuln/list?severity=CRITICAL,HIGH&limit=200
func VulnListHandler(db *gorm.DB, authService *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if requireAuth(w, r, authService) == nil {
			return
		}

		limit := 500
		type vulnRow struct {
			RepoID           string `json:"repo_id"`
			RepoSlug         string `json:"repo_slug"`
			VulnID           string `json:"vuln_id"`
			Severity         string `json:"severity"`
			PkgName          string `json:"pkg_name"`
			InstalledVersion string `json:"installed_version"`
			FixedVersion     string `json:"fixed_version"`
			Title            string `json:"title"`
		}

		var rows []vulnRow
		db.WithContext(r.Context()).Raw(`
			SELECT
				tsr.repo_id,
				COALESCE(repo.org || '/' || repo.slug, tsr.repo_id) AS repo_slug,
				vuln->>'VulnerabilityID'  AS vuln_id,
				vuln->>'Severity'         AS severity,
				vuln->>'PkgName'          AS pkg_name,
				vuln->>'InstalledVersion' AS installed_version,
				COALESCE(vuln->>'FixedVersion', '') AS fixed_version,
				COALESCE(vuln->>'Title', '')        AS title
			FROM trivy_scan_results tsr
			LEFT JOIN repos repo ON repo.id = tsr.repo_id
			CROSS JOIN LATERAL jsonb_array_elements(tsr.raw_json->'Results') AS result(result)
			CROSS JOIN LATERAL jsonb_array_elements(result.result->'Vulnerabilities') AS vuln(vuln)
			ORDER BY
				CASE vuln->>'Severity'
					WHEN 'CRITICAL' THEN 1
					WHEN 'HIGH'     THEN 2
					WHEN 'MEDIUM'   THEN 3
					WHEN 'LOW'      THEN 4
					ELSE 5
				END,
				vuln->>'VulnerabilityID'
			LIMIT ?
		`, limit).Scan(&rows)

		if rows == nil {
			rows = []vulnRow{}
		}

		writeJSON(w, http.StatusOK, rows)
	}
}

// VulnTrendHandler returns daily aggregate vulnerability counts for the last N days.
//
// GET /api/vuln/trend?days=30
func VulnTrendHandler(db *gorm.DB, authService *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if requireAuth(w, r, authService) == nil {
			return
		}

		days := 30
		if d := r.URL.Query().Get("days"); d != "" {
			if v, err := strconv.Atoi(d); err == nil && v > 0 && v <= 365 {
				days = v
			}
		}

		type trendRow struct {
			Date     string `json:"date"`
			Critical int    `json:"critical"`
			High     int    `json:"high"`
			Medium   int    `json:"medium"`
			Low      int    `json:"low"`
			Unknown  int    `json:"unknown"`
		}

		var rows []trendRow
		db.WithContext(r.Context()).Raw(`
			SELECT
				DATE(scanned_at)         AS date,
				SUM(critical_count)      AS critical,
				SUM(high_count)          AS high,
				SUM(medium_count)        AS medium,
				SUM(low_count)           AS low,
				SUM(unknown_count)       AS unknown
			FROM trivy_scan_results
			WHERE scanned_at >= now() - (? || ' days')::INTERVAL
			GROUP BY DATE(scanned_at)
			ORDER BY date ASC
		`, days).Scan(&rows)

		if rows == nil {
			rows = []trendRow{}
		}

		writeJSON(w, http.StatusOK, rows)
	}
}
