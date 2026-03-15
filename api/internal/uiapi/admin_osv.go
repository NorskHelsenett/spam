package uiapi

import (
	"encoding/json"
	"net/http"

	"github.com/NorskHelsenett/spam/internal/auth"
	"github.com/NorskHelsenett/spam/internal/jobs"
	"gorm.io/gorm"
)

// AdminOSVScanHandler enqueues an OSV_SCAN job.
// Returns 409 if a scan is already queued or running.
//
// POST /api/admin/osv/scan
func AdminOSVScanHandler(db *gorm.DB, authService *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, err := authService.RequireAdmin(r); err != nil {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}

		// Block if a scan is already active.
		var active int64
		db.WithContext(r.Context()).Model(&jobs.Job{}).
			Where("type = ? AND status IN ?", jobs.JobTypeOSVScan,
				[]jobs.JobStatus{jobs.JobStatusQueued, jobs.JobStatusRunning, jobs.JobStatusRetry}).
			Count(&active)
		if active > 0 {
			http.Error(w, "osv scan already queued or running", http.StatusConflict)
			return
		}

		job, err := jobs.CreateJob(r.Context(), db, jobs.CreateJobInput{
			Type:        jobs.JobTypeOSVScan,
			MaxAttempts: 1, // don't auto-retry a long-running scan
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

type osvScanStatus struct {
	JobID     string     `json:"job_id,omitempty"`
	Status    string     `json:"status,omitempty"`
	CreatedAt *string    `json:"created_at,omitempty"`
	FinishedAt *string   `json:"finished_at,omitempty"`
	Error     string     `json:"error,omitempty"`
	Result    interface{} `json:"result,omitempty"`
}

// AdminOSVScanStatusHandler returns the latest OSV_SCAN job status.
//
// GET /api/admin/osv/scan/status
func AdminOSVScanStatusHandler(db *gorm.DB, authService *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, err := authService.RequireAdmin(r); err != nil {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}

		var job jobs.Job
		if err := db.WithContext(r.Context()).
			Where("type = ?", jobs.JobTypeOSVScan).
			Order("created_at DESC").
			First(&job).Error; err != nil {
			// No scan has ever run.
			writeJSON(w, http.StatusOK, osvScanStatus{})
			return
		}

		createdStr := job.CreatedAt.UTC().Format("2006-01-02T15:04:05Z")
		status := osvScanStatus{
			JobID:     job.ID,
			Status:    string(job.Status),
			CreatedAt: &createdStr,
			Error:     job.Error,
		}
		if job.FinishedAt != nil {
			s := job.FinishedAt.UTC().Format("2006-01-02T15:04:05Z")
			status.FinishedAt = &s
		}
		if len(job.Result) > 0 {
			var result interface{}
			if err := json.Unmarshal(job.Result, &result); err == nil {
				status.Result = result
			} else {
				status.Result = string(job.Result)
			}
		}

		writeJSON(w, http.StatusOK, status)
	}
}
