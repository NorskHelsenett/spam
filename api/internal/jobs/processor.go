package jobs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	dbviews "github.com/NorskHelsenett/spam/internal/db"
	"github.com/NorskHelsenett/spam/internal/vulnerabilities"
	"github.com/NorskHelsenett/spam/internal/vulnmetrics"
	"gorm.io/gorm"
)

// TrivyJobCreator is implemented by the runner when K8s is available.
// It allows the worker to create an ad-hoc trivy scanner K8s job.
type TrivyJobCreator interface {
	CreateTrivyAdhocJob(ctx context.Context, cronJobName string) error
}

// retryableError wraps an error to signal the worker to retry without counting
// the attempt against the job's max attempts.
type retryableError struct{ err error }

func (e retryableError) Error() string { return e.err.Error() }
func (e retryableError) Unwrap() error { return e.err }

// IsRetryableWithoutCount reports whether the error should be retried without
// incrementing the attempt counter.
func IsRetryableWithoutCount(err error) bool {
	var t retryableError
	return errors.As(err, &t)
}

// RunExecutor is the interface for executing runs.
type RunExecutor interface {
	ExecuteRun(ctx context.Context, runID string, payload interface{}) error
}

// RunReconciler reconciles RUNNING jobs against their K8s job state.
type RunReconciler interface {
	ReconcileRunningJobs(ctx context.Context, db *gorm.DB, minAge time.Duration) (int, error)
}

// ProcessJob executes job-specific handlers.
func ProcessJob(ctx context.Context, db *gorm.DB, job *Job, runExecutor RunExecutor) (interface{}, error) {
	switch job.Type {
	case JobTypeCreateRun:
		return processCreateRun(ctx, db, job, runExecutor)
	case JobTypeRefreshSBOMViews:
		return processRefreshSBOMViews(ctx, db)
	case JobTypeOSVScan:
		return processOSVScan(ctx, db, job.ID)
	case JobTypeTrivyAdhocScan:
		return processTrivyAdhocScan(ctx, job, runExecutor)
	default:
		return nil, fmt.Errorf("unknown job type: %s", job.Type)
	}
}

func processRefreshSBOMViews(ctx context.Context, db *gorm.DB) (interface{}, error) {
	if err := dbviews.RefreshMaterializedViews(ctx, db); err != nil {
		if errors.Is(err, dbviews.ErrRefreshLockHeld) {
			// Another process holds the refresh lock. Retry without counting
			// the attempt so this job runs again once the lock is released.
			return nil, retryableError{err}
		}
		return nil, err
	}
	return map[string]string{"status": "refreshed"}, nil
}

func processOSVScan(ctx context.Context, db *gorm.DB, jobID string) (interface{}, error) {
	result, err := vulnerabilities.RunBatchScan(ctx, db, func(progress vulnerabilities.BatchScanResult) {
		if data, jsonErr := json.Marshal(progress); jsonErr == nil {
			db.WithContext(ctx).Model(&Job{}).Where("id = ?", jobID).Update("result", data)
		}
	})
	if err != nil {
		return result, err
	}
	if _, err := vulnmetrics.Refresh(ctx, db, time.Now().UTC()); err != nil {
		return result, fmt.Errorf("refresh vulnerability dashboard metrics: %w", err)
	}
	return result, nil
}

func processTrivyAdhocScan(ctx context.Context, job *Job, runExecutor RunExecutor) (interface{}, error) {
	creator, ok := runExecutor.(TrivyJobCreator)
	if !ok {
		return nil, NonRetryable(errors.New("trivy job creation not available: runner not enabled"))
	}

	// CronJob name comes from the worker's own environment — the worker owns K8s config.
	cronJobName := strings.TrimSpace(os.Getenv("TRIVY_SCANNER_CRONJOB_NAME"))
	if cronJobName == "" {
		// Fall back to payload for backwards compatibility.
		var payload TrivyAdhocPayload
		if len(job.Payload) > 0 {
			_ = json.Unmarshal(job.Payload, &payload)
		}
		cronJobName = payload.CronJobName
	}
	if cronJobName == "" {
		return nil, NonRetryable(errors.New("TRIVY_SCANNER_CRONJOB_NAME not configured on worker"))
	}

	if err := creator.CreateTrivyAdhocJob(ctx, cronJobName); err != nil {
		if isAlreadyRunning(err) {
			return nil, NonRetryable(err)
		}
		return nil, err
	}

	return map[string]string{"status": "created", "cronjob": cronJobName}, nil
}

func isAlreadyRunning(err error) bool {
	return err != nil && (strings.Contains(err.Error(), "already running") || strings.Contains(err.Error(), "AlreadyExists"))
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
	// Exponential backoff: 1min, 2min, 4min, 8min, 16min, capped at 30min
	delay := time.Minute
	for i := 1; i < attempts; i++ {
		delay *= 2
	}
	const maxDelay = 30 * time.Minute
	if delay > maxDelay {
		delay = maxDelay
	}
	return now.Add(delay)
}
