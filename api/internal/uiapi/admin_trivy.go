package uiapi

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log"
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
	ActivePods    int32  `json:"active_leases"` // field name kept for frontend compat
	ScannedCount  int64  `json:"scanned_count"`
	LastScannedAt string `json:"last_scanned_at,omitempty"`
}

type trivyJobStatusResponse struct {
	Active    int32 `json:"active"`
	Succeeded int32 `json:"succeeded"`
	Failed    int32 `json:"failed"`
}

// queryWorkerTrivyJobStatus calls the worker's internal endpoint to get K8s Job pod counts.
// Returns (0, 0, 0) silently if the worker is unreachable or not configured.
func queryWorkerTrivyJobStatus(workerURL, hmacKey string) (active, succeeded, failed int32) {
	if workerURL == "" {
		return
	}
	url := workerURL + "/api/trivy/job/status"
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return
	}

	// HMAC-sign the empty body.
	mac := hmac.New(sha256.New, []byte(hmacKey))
	req.Header.Set("X-Scanner-Signature", hex.EncodeToString(mac.Sum(nil)))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Printf("trivy job status: worker unreachable: %v", err)
		return
	}
	defer resp.Body.Close()

	var result trivyJobStatusResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return
	}
	return result.Active, result.Succeeded, result.Failed
}

// AdminTrivyScanStatusHandler returns trivy scanner statistics plus the latest ad-hoc job status.
//
// GET /api/admin/trivy/scan/status
func AdminTrivyScanStatusHandler(db *gorm.DB, authService *auth.Service, workerURL, hmacKey string) http.HandlerFunc {
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

		// Active pods from the K8s Job via the worker.
		status.ActivePods, _, _ = queryWorkerTrivyJobStatus(workerURL, hmacKey)

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
