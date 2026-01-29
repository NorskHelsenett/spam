package runner

import (
	"time"

	"gorm.io/datatypes"
)

// RunStatus represents the status of a run.
type RunStatus string

const (
	RunStatusQueued    RunStatus = "QUEUED"
	RunStatusRunning   RunStatus = "RUNNING"
	RunStatusSucceeded RunStatus = "SUCCEEDED"
	RunStatusFailed    RunStatus = "FAILED"
	RunStatusCancelled RunStatus = "CANCELLED"
)

// Run represents a runner execution (extends Job with run-specific fields).
type Run struct {
	ID              string         `gorm:"primaryKey;size:36" json:"id"`
	Type            string         `gorm:"size:128;index;not null" json:"type"`
	Status          RunStatus      `gorm:"size:16;index;not null" json:"status"`
	Payload         datatypes.JSON `gorm:"type:jsonb" json:"payload"`
	Result          datatypes.JSON `gorm:"type:jsonb" json:"result,omitempty"`
	Error           string         `gorm:"type:text" json:"error,omitempty"`
	Attempts        int            `gorm:"not null;default:0" json:"attempts"`
	MaxAttempts     int            `gorm:"not null;default:3" json:"max_attempts"`
	RunAt           time.Time      `gorm:"index" json:"run_at"`
	LockedAt        *time.Time     `gorm:"index" json:"locked_at,omitempty"`
	LockedBy        string         `gorm:"size:128" json:"locked_by,omitempty"`
	LastAttemptedAt *time.Time     `json:"last_attempted_at,omitempty"`
	FinishedAt      *time.Time     `json:"finished_at,omitempty"`
	CancelledAt     *time.Time     `json:"cancelled_at,omitempty"`
	CancelledBy     string         `gorm:"size:36" json:"cancelled_by,omitempty"`
	K8sJobName      string         `gorm:"size:255" json:"k8s_job_name,omitempty"`
	K8sNamespace    string         `gorm:"size:255" json:"k8s_namespace,omitempty"`
	CreatedAt       time.Time      `json:"created_at"`
	UpdatedAt       time.Time      `json:"updated_at"`
}

// TableName specifies the table name for Run (uses jobs table).
func (Run) TableName() string {
	return "jobs"
}

// RunLog represents a single log line from a run.
type RunLog struct {
	ID        int64     `gorm:"primaryKey;autoIncrement" json:"id"`
	RunID     string    `gorm:"size:36;not null;index:idx_run_logs_run_id;index:idx_run_logs_run_created" json:"run_id"`
	Line      string    `gorm:"type:text;not null" json:"line"`
	CreatedAt time.Time `gorm:"index:idx_run_logs_run_created" json:"created_at"`
}

// TableName specifies the table name for RunLog.
func (RunLog) TableName() string {
	return "run_logs"
}

// RunSecret stores Gitleaks findings for a run.
type RunSecret struct {
	ID           string         `gorm:"primaryKey;size:36" json:"id"`
	RunID        string         `gorm:"size:36;not null;index" json:"run_id"`
	RepoID       string         `gorm:"size:36;index" json:"repo_id,omitempty"`
	Findings     datatypes.JSON `gorm:"type:jsonb;not null" json:"findings"`
	FindingCount int            `gorm:"default:0" json:"finding_count"`
	CreatedAt    time.Time      `json:"created_at"`
}

// TableName specifies the table name for RunSecret.
func (RunSecret) TableName() string {
	return "run_secrets"
}

// CreateRunPayload is the payload for CREATE_RUN jobs.
type CreateRunPayload struct {
	RepoID    string `json:"repo_id,omitempty"`
	Provider  string `json:"provider,omitempty"`
	CloneURL  string `json:"clone_url"`
	Ref       string `json:"ref,omitempty"`
	CommitSHA string `json:"commit_sha,omitempty"`
}

// RunResultPayload is the result stored after a run completes.
type RunResultPayload struct {
	SBOMID       string `json:"sbom_id,omitempty"`
	SecretID     string `json:"secret_id,omitempty"`
	ExitCode     int    `json:"exit_code"`
	ErrorMessage string `json:"error_message,omitempty"`
}
