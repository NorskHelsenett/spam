package uiapi

import (
	"net/http"
	"time"

	"github.com/NorskHelsenett/spam/internal/auth"
	"github.com/NorskHelsenett/spam/internal/jobs"
	"gorm.io/gorm"
)

type trivyScanStatus struct {
	JobID         string `json:"job_id,omitempty"`
	JobStatus     string `json:"job_status,omitempty"`
	CreatedAt     string `json:"created_at,omitempty"`
	FinishedAt    string `json:"finished_at,omitempty"`
	Error         string `json:"error,omitempty"`
	PendingCount  int64  `json:"pending_count"`
	ActiveLeases  int64  `json:"active_leases"`
	ScannedCount  int64  `json:"scanned_count"`
	LastScannedAt string `json:"last_scanned_at,omitempty"`
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

		// Count active leases (scanner pods currently working).
		db.WithContext(r.Context()).
			Table("trivy_scan_leases").
			Where("expires_at > ?", time.Now().UTC()).
			Count(&status.ActiveLeases)

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
		if pending := totalSBOMs - status.ScannedCount; pending > 0 {
			status.PendingCount = pending
		}

		writeJSON(w, http.StatusOK, status)
	}
}

// AdminTrivyScanHandler enqueues a TRIVY_ADHOC_SCAN job.
// The worker picks it up and creates a K8s Job from the trivy-scanner CronJob.
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
