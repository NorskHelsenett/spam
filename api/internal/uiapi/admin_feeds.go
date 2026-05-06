package uiapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/NorskHelsenett/spam/internal/auth"
	"github.com/NorskHelsenett/spam/internal/jobs"
	"gorm.io/gorm"
)

// Admin manual-refresh + status endpoints for the bulk vuln feeds
// (CISA KEV, FIRST.org EPSS). Mirrors the OSV admin pattern: enqueue
// a job with run_at=now (jumps the queue), reject 409 if already
// active, expose the latest job's state for the UI to poll.
//
//   POST /api/admin/feeds/kev/refresh
//   POST /api/admin/feeds/epss/refresh
//   GET  /api/admin/feeds/status   — both feeds in one payload

// feedRefreshRequest accepts an optional reason string from the admin
// UI for the audit log. Body is optional; an empty body is fine.
type feedRefreshRequest struct {
	Reason string `json:"reason,omitempty"`
}

func feedTypeFromName(name string) (jobs.JobType, bool) {
	switch strings.ToLower(name) {
	case "kev":
		return jobs.JobTypeFetchKEV, true
	case "epss":
		return jobs.JobTypeFetchEPSS, true
	default:
		return "", false
	}
}

// AdminFeedRefreshHandler enqueues a FETCH_KEV / FETCH_EPSS job with
// run_at=now. Returns 409 if a refresh is already queued or running —
// the daily/6-hourly background schedule + a manual click should not
// double-fetch.
//
// POST /api/admin/feeds/{feed}/refresh   feed ∈ {kev, epss}
func AdminFeedRefreshHandler(db *gorm.DB, authService *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if requireAdmin(w, r, authService) == nil {
			return
		}

		jobType, ok := feedTypeFromName(r.PathValue("feed"))
		if !ok {
			http.Error(w, "unknown feed (expected kev or epss)", http.StatusBadRequest)
			return
		}

		// Decode (optional) reason — currently unused beyond audit-trail
		// readiness, but accepting the body now means we don't break the
		// UI when we add a reason column later.
		var req feedRefreshRequest
		if r.Body != nil {
			_ = json.NewDecoder(r.Body).Decode(&req)
		}

		// Block if a refresh is already active. The partial unique
		// index would also reject the insert; we check first so the
		// UI gets a clean 409 instead of a generic 500.
		var active int64
		db.WithContext(r.Context()).Model(&jobs.Job{}).
			Where("type = ? AND status IN ?", jobType,
				[]jobs.JobStatus{jobs.JobStatusQueued, jobs.JobStatusRunning, jobs.JobStatusRetry}).
			Count(&active)
		if active > 0 {
			http.Error(w, string(jobType)+" refresh already queued or running", http.StatusConflict)
			return
		}

		job, err := jobs.CreateJob(r.Context(), db, jobs.CreateJobInput{
			Type:        jobType,
			RunAt:       time.Now(),
			MaxAttempts: 1, // manual triggers don't auto-retry; admin can retrigger
		})
		if err != nil {
			http.Error(w, "failed to enqueue refresh: "+err.Error(), http.StatusInternalServerError)
			return
		}

		writeJSON(w, http.StatusAccepted, map[string]string{
			"job_id": job.ID,
			"status": string(job.Status),
			"feed":   strings.ToLower(string(jobType[len("FETCH_"):])),
		})
	}
}

type feedStatus struct {
	Feed       string          `json:"feed"`         // "kev" | "epss"
	JobID      string          `json:"job_id,omitempty"`
	Status     string          `json:"status,omitempty"`
	CreatedAt  *time.Time      `json:"created_at,omitempty"`
	StartedAt  *time.Time      `json:"started_at,omitempty"`  // = locked_at when running
	FinishedAt *time.Time      `json:"finished_at,omitempty"`
	Error      string          `json:"error,omitempty"`
	Result     json.RawMessage `json:"result,omitempty"`
	// NextScheduledAt is the run_at of the next QUEUED job for this
	// feed (set even when there's no active run — the background
	// scheduler always queues a follow-up). Lets the UI show "next
	// auto-refresh in 4h" without a second query.
	NextScheduledAt *time.Time `json:"next_scheduled_at,omitempty"`
}

type feedStatusResponse struct {
	FetchedAt time.Time    `json:"fetched_at"`
	Feeds     []feedStatus `json:"feeds"`
}

// AdminFeedsStatusHandler returns the latest FETCH_KEV / FETCH_EPSS
// job state for both feeds in one payload — the UI uses this to drive
// the progress bar and the "last refreshed" / "next scheduled" labels.
//
// GET /api/admin/feeds/status
func AdminFeedsStatusHandler(db *gorm.DB, authService *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if requireAdmin(w, r, authService) == nil {
			return
		}

		out := feedStatusResponse{
			FetchedAt: time.Now(),
			Feeds:     make([]feedStatus, 0, 2),
		}

		for _, p := range []struct {
			feedName string
			jobType  jobs.JobType
		}{
			{"kev", jobs.JobTypeFetchKEV},
			{"epss", jobs.JobTypeFetchEPSS},
		} {
			st := feedStatus{Feed: p.feedName}

			// Latest job overall (regardless of status) — drives
			// "last finished / currently running" UI.
			var latest jobs.Job
			err := db.WithContext(r.Context()).
				Where("type = ?", p.jobType).
				Order("created_at DESC").
				First(&latest).Error
			if err == nil {
				st.JobID = latest.ID
				st.Status = string(latest.Status)
				createdAt := latest.CreatedAt
				st.CreatedAt = &createdAt
				st.StartedAt = latest.LockedAt
				st.FinishedAt = latest.FinishedAt
				st.Error = latest.Error
				if len(latest.Result) > 0 {
					st.Result = json.RawMessage(latest.Result)
				}
			} else if !errors.Is(err, gorm.ErrRecordNotFound) {
				http.Error(w, "failed to load feed status", http.StatusInternalServerError)
				return
			}

			// Next scheduled run — soonest QUEUED row.
			var next jobs.Job
			err = db.WithContext(r.Context()).
				Where("type = ? AND status IN ?", p.jobType,
					[]jobs.JobStatus{jobs.JobStatusQueued, jobs.JobStatusRetry}).
				Order("run_at ASC").
				First(&next).Error
			if err == nil {
				runAt := next.RunAt
				st.NextScheduledAt = &runAt
			}

			out.Feeds = append(out.Feeds, st)
		}

		writeJSON(w, http.StatusOK, out)
	}
}
