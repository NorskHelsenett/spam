package jobs

import (
	"context"
	"errors"
	"time"

	"github.com/NorskHelsenett/spam/internal/events"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// ClaimNextJob selects the next available job and marks it RUNNING.
// Optional excludeTypes can be passed to skip certain job types (e.g., when at concurrency limit for runs).
func ClaimNextJob(ctx context.Context, db *gorm.DB, workerID string, now time.Time, excludeTypes ...JobType) (*Job, error) {
	var claimed *Job

	if err := db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var job Job
		query := tx.
			Clauses(clause.Locking{Strength: "UPDATE", Options: "SKIP LOCKED"}).
			Where("status IN ? AND run_at <= ?", []JobStatus{JobStatusQueued, JobStatusRetry}, now)

		if len(excludeTypes) > 0 {
			query = query.Where("type NOT IN ?", excludeTypes)
		}

		if err := query.
			Order("run_at asc, created_at asc").
			First(&job).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return nil
			}
			return err
		}

		previous := job.Status
		attemptedAt := now
		updates := map[string]interface{}{
			"status":            JobStatusRunning,
			"locked_at":         attemptedAt,
			"locked_by":         workerID,
			"attempts":          job.Attempts + 1,
			"last_attempted_at": attemptedAt,
			"updated_at":        attemptedAt,
		}

		if err := tx.Model(&job).Updates(updates).Error; err != nil {
			return err
		}

		job.Status = JobStatusRunning
		job.LockedAt = &attemptedAt
		job.LockedBy = workerID
		job.Attempts++
		job.LastAttemptedAt = &attemptedAt

		if err := events.EmitEvent(tx, events.EventJobStatusChanged, "job", job.ID, JobEventPayload{
			JobID:       job.ID,
			Type:        job.Type,
			Status:      job.Status,
			Previous:    previous,
			Attempts:    job.Attempts,
			MaxAttempts: job.MaxAttempts,
			RunAt:       job.RunAt,
		}); err != nil {
			return err
		}

		claimed = &job
		return nil
	}); err != nil {
		return nil, err
	}

	return claimed, nil
}

// CountRunningByType returns the number of jobs of a given type currently in RUNNING status.
func CountRunningByType(ctx context.Context, db *gorm.DB, jobType JobType) (int64, error) {
	var count int64
	if err := db.WithContext(ctx).Model(&Job{}).
		Where("type = ? AND status = ?", jobType, JobStatusRunning).
		Count(&count).Error; err != nil {
		return 0, err
	}
	return count, nil
}

// RequeueStaleJobs moves stale RUNNING jobs back to RETRY for safe restarts.
// It catches two cases:
// 1. Jobs with locked_at < staleBefore (worker crashed while processing)
// 2. Jobs with NULL locked_at but updated_at < staleBefore (async runs like CREATE_RUN that never completed)
func RequeueStaleJobs(ctx context.Context, db *gorm.DB, staleBefore time.Time, now time.Time) (int, error) {
	var jobs []Job
	updated := 0

	if err := db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.
			Clauses(clause.Locking{Strength: "UPDATE", Options: "SKIP LOCKED"}).
			Where("status = ?", JobStatusRunning).
			Where("(locked_at < ? OR (locked_at IS NULL AND updated_at < ?))", staleBefore, staleBefore).
			Find(&jobs).Error; err != nil {
			return err
		}

		for i := range jobs {
			job := jobs[i]
			previous := job.Status
			runAt := NextRetryTime(job.Attempts, job.MaxAttempts, now)
			updates := map[string]interface{}{
				"status":     JobStatusRetry,
				"locked_at":  nil,
				"locked_by":  "",
				"run_at":     runAt,
				"updated_at": now,
			}

			if err := tx.Model(&job).Updates(updates).Error; err != nil {
				return err
			}

			job.Status = JobStatusRetry
			job.RunAt = runAt

			if err := events.EmitEvent(tx, events.EventJobStatusChanged, "job", job.ID, JobEventPayload{
				JobID:       job.ID,
				Type:        job.Type,
				Status:      job.Status,
				Previous:    previous,
				Attempts:    job.Attempts,
				MaxAttempts: job.MaxAttempts,
				RunAt:       job.RunAt,
			}); err != nil {
				return err
			}

			updated++
		}

		return nil
	}); err != nil {
		return 0, err
	}

	return updated, nil
}
