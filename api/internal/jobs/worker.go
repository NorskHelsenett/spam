package jobs

import (
	"context"
	"errors"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

func usesExtendedStaleTimeout(jobType JobType) bool {
	return jobType == JobTypeCreateRun
}

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

		claimed = &job
		return nil
	}); err != nil {
		return nil, err
	}

	return claimed, nil
}

// ClaimNextJobOfType is the inclusive counterpart to ClaimNextJob: it only
// claims jobs of the given type. Used by dedicated scanner pods
// (image-scanner, sbom-scanner) that own a specific job type end-to-end and
// should not accidentally pick up unrelated work.
func ClaimNextJobOfType(ctx context.Context, db *gorm.DB, workerID string, now time.Time, jobType JobType) (*Job, error) {
	var claimed *Job

	if err := db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var job Job
		err := tx.
			Clauses(clause.Locking{Strength: "UPDATE", Options: "SKIP LOCKED"}).
			Where("type = ? AND status IN ? AND run_at <= ?", jobType,
				[]JobStatus{JobStatusQueued, JobStatusRetry}, now).
			Order("run_at asc, created_at asc").
			First(&job).Error
		if err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return nil
			}
			return err
		}

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
// CREATE_RUN keeps the longer async timeout. In-process jobs such as OSV scans
// can be reclaimed much sooner because they heartbeat while running.
func RequeueStaleJobs(ctx context.Context, db *gorm.DB, syncStaleBefore, asyncStaleBefore, now time.Time) (int, error) {
	var jobs []Job
	updated := 0

	if err := db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.
			Clauses(clause.Locking{Strength: "UPDATE", Options: "SKIP LOCKED"}).
			Where("status = ?", JobStatusRunning).
			Where(`
				(
					type = ? AND (locked_at < ? OR (locked_at IS NULL AND updated_at < ?))
				) OR (
					type <> ? AND (locked_at < ? OR (locked_at IS NULL AND updated_at < ?))
				)
			`, JobTypeCreateRun, asyncStaleBefore, asyncStaleBefore, JobTypeCreateRun, syncStaleBefore, syncStaleBefore).
			Find(&jobs).Error; err != nil {
			return err
		}

		for i := range jobs {
			job := jobs[i]
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

			updated++
		}

		return nil
	}); err != nil {
		return 0, err
	}

	return updated, nil
}
