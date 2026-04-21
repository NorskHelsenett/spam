package jobs

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"gorm.io/datatypes"
	"gorm.io/gorm"
)

type CreateJobInput struct {
	Type        string
	Payload     interface{}
	RunAt       time.Time
	MaxAttempts int
}

// CreateJob inserts a new queued job.
func CreateJob(ctx context.Context, db *gorm.DB, input CreateJobInput) (*Job, error) {
	if input.Type == "" {
		return nil, errors.New("job type required")
	}

	var job Job
	if err := db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		created, err := CreateJobTx(ctx, tx, input)
		if err != nil {
			return err
		}
		job = *created
		return nil
	}); err != nil {
		return nil, err
	}

	return &job, nil
}

// CreateJobTx inserts a job inside an existing transaction.
func CreateJobTx(ctx context.Context, tx *gorm.DB, input CreateJobInput) (*Job, error) {
	if input.Type == "" {
		return nil, errors.New("job type required")
	}

	runAt := input.RunAt
	if runAt.IsZero() {
		runAt = time.Now()
	}

	maxAttempts := input.MaxAttempts
	if maxAttempts <= 0 {
		maxAttempts = 3
	}

	payloadJSON, err := marshalPayload(input.Payload)
	if err != nil {
		return nil, err
	}

	job := Job{
		ID:          uuid.NewString(),
		Type:        input.Type,
		Status:      JobStatusQueued,
		Payload:     payloadJSON,
		MaxAttempts: maxAttempts,
		RunAt:       runAt,
	}

	if err := tx.WithContext(ctx).Create(&job).Error; err != nil {
		return nil, err
	}

	return &job, nil
}

// UpdateJobStatus changes a job status.
func UpdateJobStatus(ctx context.Context, db *gorm.DB, jobID string, status JobStatus, result interface{}, errText string, nextRunAt *time.Time) (*Job, error) {
	var updated Job

	if err := db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.First(&updated, "id = ?", jobID).Error; err != nil {
			return err
		}

		now := time.Now()

		resultJSON, err := marshalPayload(result)
		if err != nil {
			return err
		}

		updates := map[string]interface{}{
			"status":            status,
			"result":            resultJSON,
			"error":             errText,
			"locked_at":         nil,
			"locked_by":         "",
			"last_attempted_at": updated.LastAttemptedAt,
			"updated_at":        now,
		}

		if status == JobStatusSucceeded || status == JobStatusFailed {
			updates["finished_at"] = now
		}
		if status == JobStatusRetry {
			if nextRunAt != nil && !nextRunAt.IsZero() {
				updates["run_at"] = *nextRunAt
			} else {
				updates["run_at"] = now
			}
		}

		if err := tx.Model(&updated).Updates(updates).Error; err != nil {
			return err
		}

		updated.Status = status
		updated.Error = errText
		if status == JobStatusSucceeded || status == JobStatusFailed {
			updated.FinishedAt = &now
		}
		if status == JobStatusRetry {
			runAt := now
			if nextRunAt != nil && !nextRunAt.IsZero() {
				runAt = *nextRunAt
			}
			updated.RunAt = runAt
		}
		updated.Result = resultJSON

		return nil
	}); err != nil {
		return nil, err
	}

	return &updated, nil
}

func marshalPayload(payload interface{}) (datatypes.JSON, error) {
	if payload == nil {
		return nil, nil
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	return datatypes.JSON(data), nil
}
