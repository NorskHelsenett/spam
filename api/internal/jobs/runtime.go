package jobs

import (
	"context"
	"time"

	"gorm.io/gorm"
)

const JobHeartbeatInterval = 10 * time.Second

func ShouldHeartbeat(jobType JobType) bool {
	return !usesExtendedStaleTimeout(jobType)
}

// HeartbeatJob periodically refreshes the lock timestamp for an in-process job
// so stale-job recovery can distinguish live work from an interrupted worker.
func HeartbeatJob(ctx context.Context, db *gorm.DB, jobID, workerID string, interval time.Duration) {
	if interval <= 0 {
		interval = JobHeartbeatInterval
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			db.WithContext(ctx).
				Model(&Job{}).
				Where("id = ? AND status = ? AND locked_by = ?", jobID, JobStatusRunning, workerID).
				Updates(map[string]any{
					"locked_at":  now,
					"updated_at": now,
				})
		}
	}
}
