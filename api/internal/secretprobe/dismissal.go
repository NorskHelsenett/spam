package secretprobe

import "time"

// SecretDismissal records that a user has dismissed a secret finding.
type SecretDismissal struct {
	SecretHash  string    `gorm:"primaryKey;size:64" json:"secret_hash"`
	DismissedBy string    `gorm:"size:256;not null" json:"dismissed_by"`
	DismissedAt time.Time `gorm:"not null" json:"dismissed_at"`
}
