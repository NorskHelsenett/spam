package jobs

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/NorskHelsenett/spam/internal/events"
	"github.com/NorskHelsenett/spam/internal/models"
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

type JobEventPayload struct {
	JobID       string           `json:"job_id"`
	Type        string           `json:"type"`
	Status      models.JobStatus `json:"status"`
	Previous    models.JobStatus `json:"previous,omitempty"`
	Attempts    int              `json:"attempts"`
	MaxAttempts int              `json:"max_attempts"`
	RunAt       time.Time        `json:"run_at"`
}

// CreateJob inserts a new queued job and emits a JOB_CREATED event.
func CreateJob(ctx context.Context, db *gorm.DB, input CreateJobInput) (*models.Job, error) {
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

	job := models.Job{
		ID:          uuid.NewString(),
		Type:        input.Type,
		Status:      models.JobStatusQueued,
		Payload:     payloadJSON,
		MaxAttempts: maxAttempts,
		RunAt:       runAt,
	}

	if err := db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(&job).Error; err != nil {
			return err
		}

		return events.EmitEvent(tx, events.EventJobCreated, "job", job.ID, JobEventPayload{
			JobID:       job.ID,
			Type:        job.Type,
			Status:      job.Status,
			Attempts:    job.Attempts,
			MaxAttempts: job.MaxAttempts,
			RunAt:       job.RunAt,
		})
	}); err != nil {
		return nil, err
	}

	return &job, nil
}

// UpdateJobStatus changes a job status and emits a JOB_STATUS_CHANGED event.
func UpdateJobStatus(ctx context.Context, db *gorm.DB, jobID string, status models.JobStatus, result interface{}, errText string, nextRunAt *time.Time) (*models.Job, error) {
	var updated models.Job

	if err := db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.First(&updated, "id = ?", jobID).Error; err != nil {
			return err
		}

		previous := updated.Status
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

		if status == models.JobStatusSucceeded || status == models.JobStatusFailed {
			updates["finished_at"] = now
		}
		if status == models.JobStatusRetry {
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
		if status == models.JobStatusSucceeded || status == models.JobStatusFailed {
			updated.FinishedAt = &now
		}
		if status == models.JobStatusRetry {
			runAt := now
			if nextRunAt != nil && !nextRunAt.IsZero() {
				runAt = *nextRunAt
			}
			updated.RunAt = runAt
		}
		updated.Result = resultJSON

		return events.EmitEvent(tx, events.EventJobStatusChanged, "job", updated.ID, JobEventPayload{
			JobID:       updated.ID,
			Type:        updated.Type,
			Status:      updated.Status,
			Previous:    previous,
			Attempts:    updated.Attempts,
			MaxAttempts: updated.MaxAttempts,
			RunAt:       updated.RunAt,
		})
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
