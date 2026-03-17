package secretprobe

import "time"

// Status represents the outcome of a secret probe.
type Status string

const (
	StatusValid         Status = "valid"
	StatusInvalid       Status = "invalid"
	StatusRevoked       Status = "revoked"
	StatusExpired       Status = "expired"
	StatusFalsePositive Status = "false_positive"
	StatusUnknown       Status = "unknown"
	StatusError         Status = "error"
)

// SecretProbe stores the result of probing a discovered secret.
// The actual secret value is never stored — only a SHA-256 hash for dedup.
type SecretProbe struct {
	SecretHash string    `gorm:"primaryKey;size:64" json:"secret_hash"`
	RuleID     string    `gorm:"size:128;not null;index" json:"rule_id"`
	Status     Status    `gorm:"size:32;not null" json:"status"`
	Reason     string    `gorm:"size:512" json:"reason,omitempty"`
	Metadata   string    `gorm:"type:jsonb;default:'{}'" json:"metadata,omitempty"`
	ProbedAt   time.Time `gorm:"not null" json:"probed_at"`
}

// ProbeOutput is returned by individual probe functions.
type ProbeOutput struct {
	Status   Status
	Reason   string
	Metadata map[string]any
}
