package jobs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	dbviews "github.com/NorskHelsenett/spam/internal/db"
	"gorm.io/gorm"
)

// RunExecutor is the interface for executing runs.
type RunExecutor interface {
	ExecuteRun(ctx context.Context, runID string, payload interface{}) error
}

// ProcessJob executes job-specific handlers.
func ProcessJob(ctx context.Context, db *gorm.DB, job *Job, runExecutor RunExecutor) (interface{}, error) {
	switch job.Type {
	case JobTypeCreateRun:
		return processCreateRun(ctx, db, job, runExecutor)
	case JobTypeRefreshSBOMViews:
		return processRefreshSBOMViews(ctx, db)
	default:
		return nil, fmt.Errorf("unknown job type: %s", job.Type)
	}
}

func processRefreshSBOMViews(ctx context.Context, db *gorm.DB) (interface{}, error) {
	if err := dbviews.RefreshMaterializedViews(ctx, db); err != nil {
		return nil, err
	}
	return map[string]string{"status": "refreshed"}, nil
}

func processCreateRun(ctx context.Context, db *gorm.DB, job *Job, runExecutor RunExecutor) (interface{}, error) {
	if runExecutor == nil {
		return nil, errors.New("runner not enabled")
	}

	var payload CreateRunPayload
	if len(job.Payload) == 0 {
		return nil, errors.New("missing job payload")
	}
	if err := json.Unmarshal(job.Payload, &payload); err != nil {
		return nil, fmt.Errorf("unmarshal payload: %w", err)
	}
	if payload.CloneURL == "" {
		return nil, errors.New("missing clone_url in payload")
	}

	if err := runExecutor.ExecuteRun(ctx, job.ID, payload); err != nil {
		return nil, fmt.Errorf("execute run: %w", err)
	}

	return map[string]string{
		"status": "started",
		"run_id": job.ID,
	}, nil
}

func NextRetryTime(attempts, maxAttempts int, now time.Time) time.Time {
	if maxAttempts <= 0 {
		maxAttempts = 3
	}
	delay := time.Minute
	if attempts > 1 {
		delay = time.Duration(attempts) * time.Minute
	}
	return now.Add(delay)
}
