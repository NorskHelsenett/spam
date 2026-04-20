package uiapi

import (
	"net/http"
	"time"

	"github.com/NorskHelsenett/spam/internal/auth"
	"github.com/NorskHelsenett/spam/internal/jobs"
	"gorm.io/gorm"
)

type trivyRun struct {
	StartedAt     string `json:"started_at"`
	FinishedAt    string `json:"finished_at"`
	SBOMCount     int64  `json:"sbom_count"`
	CriticalCount int64  `json:"critical_count"`
	HighCount     int64  `json:"high_count"`
}

type trivyScanStatus struct {
	JobID         string     `json:"job_id,omitempty"`
	JobStatus     string     `json:"job_status,omitempty"`
	CreatedAt     string     `json:"created_at,omitempty"`
	FinishedAt    string     `json:"finished_at,omitempty"`
	Error         string     `json:"error,omitempty"`
	PendingCount  int64      `json:"pending_count"`
	ScannedCount  int64      `json:"scanned_count"`
	LastScannedAt string     `json:"last_scanned_at,omitempty"`
	ScanComplete  bool       `json:"scan_complete"`
	RecentRuns    []trivyRun `json:"recent_runs"`
}

// AdminTrivyScanStatusHandler returns trivy scanner statistics plus the latest ad-hoc job status.
//
// GET /api/admin/trivy/scan/status
func AdminTrivyScanStatusHandler(db *gorm.DB, authService *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, err := authService.RequireAdmin(r); err != nil {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}

		var status trivyScanStatus

		// Most recent TRIVY_ADHOC_SCAN job.
		var job jobs.Job
		if err := db.WithContext(r.Context()).
			Where("type = ?", jobs.JobTypeTrivyAdhocScan).
			Order("created_at DESC").
			First(&job).Error; err == nil {
			status.JobID = job.ID
			status.JobStatus = string(job.Status)
			status.CreatedAt = job.CreatedAt.UTC().Format("2006-01-02T15:04:05Z")
			status.Error = job.Error
			if job.FinishedAt != nil {
				status.FinishedAt = job.FinishedAt.UTC().Format("2006-01-02T15:04:05Z")
			}
		}

		// Count distinct scanned SBOMs.
		db.WithContext(r.Context()).
			Table("trivy_scan_results").
			Distinct("sbom_id").
			Count(&status.ScannedCount)

		// Last scan timestamp.
		var lastAt time.Time
		if err := db.WithContext(r.Context()).
			Table("trivy_scan_results").
			Select("MAX(scanned_at)").
			Row().Scan(&lastAt); err == nil && !lastAt.IsZero() {
			status.LastScannedAt = lastAt.UTC().Format("2006-01-02T15:04:05Z")
		}

		// Pending = total SBOMs minus scanned.
		var totalSBOMs int64
		db.WithContext(r.Context()).Table("sboms").Count(&totalSBOMs)
		pending := totalSBOMs - status.ScannedCount
		if pending > 0 {
			status.PendingCount = pending
		} else {
			status.ScanComplete = true
		}

		// Recent runs: group scan results by day, last 10.
		type runRow struct {
			Day           time.Time
			StartedAt     time.Time
			FinishedAt    time.Time
			SBOMCount     int64
			CriticalCount int64
			HighCount     int64
		}
		var rows []runRow
		db.WithContext(r.Context()).Raw(`
			SELECT
				DATE_TRUNC('day', scanned_at) AS day,
				MIN(scanned_at)               AS started_at,
				MAX(scanned_at)               AS finished_at,
				COUNT(DISTINCT sbom_id)       AS sbom_count,
				SUM(critical_count)           AS critical_count,
				SUM(high_count)               AS high_count
			FROM trivy_scan_results
			GROUP BY DATE_TRUNC('day', scanned_at)
			ORDER BY day DESC
			LIMIT 10
		`).Scan(&rows)
		status.RecentRuns = make([]trivyRun, 0, len(rows))
		for _, row := range rows {
			status.RecentRuns = append(status.RecentRuns, trivyRun{
				StartedAt:     row.StartedAt.UTC().Format("2006-01-02T15:04:05Z"),
				FinishedAt:    row.FinishedAt.UTC().Format("2006-01-02T15:04:05Z"),
				SBOMCount:     row.SBOMCount,
				CriticalCount: row.CriticalCount,
				HighCount:     row.HighCount,
			})
		}

		writeJSON(w, http.StatusOK, status)
	}
}

// AdminTrivyScanHandler enqueues a TRIVY_ADHOC_SCAN job.
// The worker picks it up and creates a K8s Job from the sbom-scanner CronJob.
// Returns 409 if a job is already active.
//
// POST /api/admin/trivy/scan
func AdminTrivyScanHandler(db *gorm.DB, authService *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, err := authService.RequireAdmin(r); err != nil {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}

		// Block if a job is already active.
		var active int64
		db.WithContext(r.Context()).Model(&jobs.Job{}).
			Where("type = ? AND status IN ?", jobs.JobTypeTrivyAdhocScan,
				[]jobs.JobStatus{jobs.JobStatusQueued, jobs.JobStatusRunning, jobs.JobStatusRetry}).
			Count(&active)
		if active > 0 {
			http.Error(w, "trivy scan job already queued or running", http.StatusConflict)
			return
		}

		job, err := jobs.CreateJob(r.Context(), db, jobs.CreateJobInput{
			Type:        jobs.JobTypeTrivyAdhocScan,
			MaxAttempts: 2,
		})
		if err != nil {
			http.Error(w, "failed to enqueue scan: "+err.Error(), http.StatusInternalServerError)
			return
		}

		writeJSON(w, http.StatusAccepted, map[string]string{
			"job_id": job.ID,
			"status": string(job.Status),
		})
	}
}
