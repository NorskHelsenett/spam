package runner

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/NorskHelsenett/spam/internal/jobs"
	"github.com/NorskHelsenett/spam/internal/signingpolicy"
	"github.com/NorskHelsenett/spam/internal/vulnmetrics"
	"gorm.io/gorm"
)

// imageScanRunTokenTTL is the lifetime of the per-job upload token minted at
// lease time. Long enough that a slow image pull + scan + upload fits
// comfortably inside one token; short enough that a crashed scanner can't
// hand the token to something else hours later.
const imageScanRunTokenTTL = 2 * time.Hour

// imageScanLeaseResponse is the payload delivered to a scanner pod when it
// calls /api/image-scans/next. Mirrors jobs.ImageScanPayload but with the
// job ID promoted to top-level so the scanner can POST results without
// needing to decode the payload twice. RunToken is a short-lived
// per-job bearer accepted by /runner/image-results — re-using that handler
// keeps upload logic in one place and avoids duplicating multipart parsing
// under HMAC auth.
type imageScanLeaseResponse struct {
	JobID         string                       `json:"job_id"`
	ImageDigestID string                       `json:"image_digest_id"`
	Registry      string                       `json:"registry"`
	Repository    string                       `json:"repository"`
	Digest        string                       `json:"digest"`
	Scanners      map[string]string            `json:"scanners,omitempty"`
	SigningPolicy *jobs.ImageScanSigningPolicy `json:"signing_policy,omitempty"`
	RunToken      string                       `json:"run_token"`
	WorkerURL     string                       `json:"worker_url"`
}

// handleImageScanNext leases the next QUEUED/RETRY IMAGE_SCAN job. The
// scanner pod calls this in a loop until it gets 204 (queue empty) and then
// exits so a fresh CronJob tick can start with a fresh vuln DB.
func (s *Server) handleImageScanNext(w http.ResponseWriter, r *http.Request) {
	leasedBy, _ := os.Hostname()
	if leasedBy == "" {
		leasedBy = "image-scanner"
	}

	job, err := jobs.ClaimNextJobOfType(r.Context(), s.db, leasedBy, time.Now(), jobs.JobTypeImageScan)
	if err != nil {
		log.Printf("image-scans/next: claim: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if job == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	var payload jobs.ImageScanPayload
	if len(job.Payload) > 0 {
		if err := json.Unmarshal(job.Payload, &payload); err != nil {
			// Claim succeeded but payload is corrupt — fail the job so
			// the scanner doesn't hang on it.
			log.Printf("image-scans/next: bad payload on job %s: %v", job.ID, err)
			_, _ = jobs.UpdateJobStatus(r.Context(), s.db, job.ID, jobs.JobStatusFailed, nil, "corrupt payload", nil)
			http.Error(w, "corrupt payload on claimed job", http.StatusInternalServerError)
			return
		}
	}

	token, err := GenerateRunToken(s.cfg.HMACKey, job.ID, imageScanRunTokenTTL)
	if err != nil {
		log.Printf("image-scans/next: mint token: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Look up the active cosign verification policy and embed it in
	// the lease response. Reading at lease-time (rather than at job-
	// enqueue time) means an admin policy change takes effect on the
	// next scan without requeueing every job in the backlog. Lookup
	// failures are non-fatal — the runner falls back to `cosign tree`
	// only, which preserves today's behaviour.
	policy := loadActiveSigningPolicy(r.Context(), s.db, s.cfg.ProviderSecretsKey)

	resp := imageScanLeaseResponse{
		JobID:         job.ID,
		ImageDigestID: payload.ImageDigestID,
		Registry:      payload.Registry,
		Repository:    payload.Repository,
		Digest:        payload.Digest,
		Scanners:      payload.Scanners,
		SigningPolicy: policy,
		RunToken:      token,
		WorkerURL:     s.cfg.WorkerURL,
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// handleImageScanPending returns the count of IMAGE_SCAN jobs that are
// ready to be claimed (QUEUED or RETRY with run_at <= now). The scanner
// pod calls this on startup BEFORE downloading the grype DB so it can
// short-circuit and exit without ~60s of DB download when there's
// nothing to scan. Non-claiming — this does not mark any job RUNNING.
func (s *Server) handleImageScanPending(w http.ResponseWriter, r *http.Request) {
	var count int64
	err := s.db.WithContext(r.Context()).
		Table("jobs").
		Where("type = ? AND status IN ? AND run_at <= ?",
			jobs.JobTypeImageScan,
			[]jobs.JobStatus{jobs.JobStatusQueued, jobs.JobStatusRetry},
			time.Now()).
		Count(&count).Error
	if err != nil {
		log.Printf("image-scans/pending: count: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]int64{"pending": count})
}

// imageScanCompleteRequest is the body of /api/image-scans/:job_id/complete.
// Status is the terminal state ("succeeded" or "failed"). ErrorMessage is
// only meaningful for "failed" but tolerated either way. PartialFailures is
// populated when the scanner ran but some categories (e.g. syft, grype)
// exited non-zero — the job still counts as succeeded if at least one
// artifact uploaded, but the rescan sweep and UI need the per-category
// breakdown so missing SBOMs don't look like clean runs.
type imageScanCompleteRequest struct {
	Status          string            `json:"status"`
	ErrorMessage    string            `json:"error,omitempty"`
	PartialFailures map[string]string `json:"partial_failures,omitempty"`
}

// handleImageScanComplete marks an IMAGE_SCAN job as terminal. The scanner
// pod calls this after uploading results (so status==succeeded implies the
// artifacts are already persisted).
func (s *Server) handleImageScanComplete(w http.ResponseWriter, r *http.Request) {
	jobID := r.PathValue("job_id")
	if jobID == "" {
		http.Error(w, "job_id required", http.StatusBadRequest)
		return
	}

	var body imageScanCompleteRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid body", http.StatusBadRequest)
		return
	}

	var job jobs.Job
	if err := s.db.WithContext(r.Context()).First(&job, "id = ?", jobID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			http.Error(w, "job not found", http.StatusNotFound)
			return
		}
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if job.Type != jobs.JobTypeImageScan {
		http.Error(w, "job is not an image scan", http.StatusForbidden)
		return
	}

	var status jobs.JobStatus
	var nextRunAt *time.Time
	switch body.Status {
	case "succeeded":
		status = jobs.JobStatusSucceeded
	case "failed":
		status = jobs.JobStatusFailed
	case "retry":
		// Transient scanner-side failure (upload timeout, 5xx). Push
		// the job back into RETRY with exponential backoff so another
		// scanner pod picks it up later. If we've exhausted
		// max_attempts, honour that and mark FAILED so the queue
		// doesn't thrash.
		if job.Attempts >= job.MaxAttempts {
			status = jobs.JobStatusFailed
			break
		}
		status = jobs.JobStatusRetry
		rt := jobs.NextRetryTime(job.Attempts, job.MaxAttempts, time.Now())
		nextRunAt = &rt
	default:
		http.Error(w, "status must be 'succeeded', 'failed', or 'retry'", http.StatusBadRequest)
		return
	}

	result := map[string]any{"status": body.Status}
	if len(body.PartialFailures) > 0 {
		result["partial_failures"] = body.PartialFailures
	}
	if _, err := jobs.UpdateJobStatus(r.Context(), s.db, jobID, status, result, body.ErrorMessage, nextRunAt); err != nil {
		log.Printf("image-scans/complete: update status: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Mark ImageScanRun finished if a row exists (the scanner creates
	// one on first artifact upload; an empty-result scan may not have
	// uploaded anything, so this is best-effort — but surface errors so a
	// broken UPDATE doesn't silently leave rows with finished_at IS NULL).
	now := time.Now().UTC()
	if err := s.db.WithContext(r.Context()).Exec(
		"UPDATE image_scan_runs SET finished_at = ?, updated_at = ? WHERE id = ? AND finished_at IS NULL",
		now, now, jobID,
	).Error; err != nil {
		log.Printf("image-scans/complete: mark finished %s: %v", jobID, err)
	}

	// image_scan_runs.finished_at is one of the four watermarks the
	// vulnmetrics cache is versioned against. Warm the cache in the
	// background so the next /app/vulnerabilities load sees fresh
	// aggregates without paying the recompute on the UI thread.
	vulnmetrics.TriggerRefresh(s.db)
	jobs.EnqueueMissingVulnMeta(r.Context(), s.db)

	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

// loadActiveSigningPolicy returns the runtime-shaped policy for the
// image-scan lease handler. Returns nil when no policy is configured
// or when it's disabled — both cases mean "fall back to cosign tree
// only", preserving today's behaviour without surprising the runner.
func loadActiveSigningPolicy(ctx context.Context, db *gorm.DB, secretsKey []byte) *jobs.ImageScanSigningPolicy {
	store := signingpolicy.NewStore(db, secretsKey)
	resolved, err := store.GetEnabled(ctx)
	if err != nil {
		return nil
	}
	return &jobs.ImageScanSigningPolicy{
		Type:                string(resolved.Type),
		Issuer:              resolved.Issuer,
		SubjectPattern:      resolved.SubjectPattern,
		KeyPEM:              resolved.KeyPEM,
		SignatureRepository: resolved.SignatureRepository,
		FulcioURL:           resolved.FulcioURL,
		RekorURL:            resolved.RekorURL,
		TUFMirrorURL:        resolved.TUFMirrorURL,
	}
}
