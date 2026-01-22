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
func ClaimNextJob(ctx context.Context, db *gorm.DB, workerID string, now time.Time) (*Job, error) {
	var claimed *Job

	if err := db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var job Job
		if err := tx.
			Clauses(clause.Locking{Strength: "UPDATE", Options: "SKIP LOCKED"}).
			Where("status IN ? AND run_at <= ?", []JobStatus{JobStatusQueued, JobStatusRetry}, now).
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

// RequeueStaleJobs moves stale RUNNING jobs back to RETRY for safe restarts.
func RequeueStaleJobs(ctx context.Context, db *gorm.DB, staleBefore time.Time, now time.Time) (int, error) {
	var jobs []Job
	updated := 0

	if err := db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.
			Clauses(clause.Locking{Strength: "UPDATE", Options: "SKIP LOCKED"}).
			Where("status = ? AND locked_at < ?", JobStatusRunning, staleBefore).
			Find(&jobs).Error; err != nil {
			return err
		}

		for i := range jobs {
			job := jobs[i]
			previous := job.Status
			updates := map[string]interface{}{
				"status":     JobStatusRetry,
				"locked_at":  nil,
				"locked_by":  "",
				"run_at":     now,
				"updated_at": now,
			}

			if err := tx.Model(&job).Updates(updates).Error; err != nil {
				return err
			}

			job.Status = JobStatusRetry
			job.RunAt = now

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
