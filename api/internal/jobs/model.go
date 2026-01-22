package jobs

import (
	"time"

	"gorm.io/datatypes"
)

type JobStatus string

const (
	JobStatusQueued    JobStatus = "QUEUED"
	JobStatusRunning   JobStatus = "RUNNING"
	JobStatusSucceeded JobStatus = "SUCCEEDED"
	JobStatusFailed    JobStatus = "FAILED"
	JobStatusRetry     JobStatus = "RETRY"
)

// Job represents a background job with lifecycle state.
type Job struct {
	ID              string         `gorm:"primaryKey;size:36"`
	Type            string         `gorm:"size:128;index;not null"`
	Status          JobStatus      `gorm:"size:16;index;not null"`
	Payload         datatypes.JSON `gorm:"type:jsonb"`
	Result          datatypes.JSON `gorm:"type:jsonb"`
	Error           string         `gorm:"type:text"`
	Attempts        int            `gorm:"not null;default:0"`
	MaxAttempts     int            `gorm:"not null;default:3"`
	RunAt           time.Time      `gorm:"index"`
	LockedAt        *time.Time     `gorm:"index"`
	LockedBy        string         `gorm:"size:128"`
	LastAttemptedAt *time.Time
	FinishedAt      *time.Time
	CreatedAt       time.Time
	UpdatedAt       time.Time
}
