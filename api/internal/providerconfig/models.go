package providerconfig

import (
	"time"

	"gorm.io/datatypes"
)

const (
	ProviderHealthUnknown  = "UNKNOWN"
	ProviderHealthHealthy  = "HEALTHY"
	ProviderHealthDegraded = "DEGRADED"
	ProviderHealthFailed   = "FAILED"
)

// ProviderInstance represents a configured Git provider instance or org.
type ProviderInstance struct {
	ID              string     `gorm:"primaryKey;size:36" json:"id"`
	Type            string     `gorm:"size:16;not null;uniqueIndex:ux_provider_identity,priority:1" json:"type"`
	BaseURL         string     `gorm:"size:512;not null;uniqueIndex:ux_provider_identity,priority:2" json:"base_url"`
	OwnerPath       string     `gorm:"size:512;not null;default:'';uniqueIndex:ux_provider_identity,priority:3" json:"owner_path"`
	DisplayName     string     `gorm:"size:512;not null" json:"display_name"`
	Enabled         bool       `gorm:"not null;default:true" json:"enabled"`
	PollInterval    *int       `gorm:"column:poll_interval;default:3600" json:"poll_interval,omitempty"`
	LastPolledAt    *time.Time `gorm:"column:last_polled_at" json:"last_polled_at,omitempty"`
	HealthStatus    string     `gorm:"size:16;not null;default:UNKNOWN" json:"health_status"`
	HealthMessage   string     `gorm:"size:1024" json:"health_message,omitempty"`
	LastHealthCheck *time.Time `json:"last_health_check,omitempty"`
	CreatedByUserID string     `gorm:"size:36" json:"created_by"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`

	// DefaultGrants holds subject pairs that receive an ingest_default
	// acl_grant for every newly discovered repo under this provider.
	// Shape: [{"subject_type":"group"|"user","subject_id":"..."}, ...].
	// Empty/null means "no automatic grants" — admins claim each repo
	// manually via /api/admin/acl/grants.
	DefaultGrants datatypes.JSON `gorm:"type:jsonb" json:"default_grants,omitempty"`
}

// ProviderSecret stores encrypted PATs for provider instances.
// Old secrets are preserved (with RevokedAt set) for audit history.
type ProviderSecret struct {
	ID               string           `gorm:"primaryKey;size:36" json:"id"`
	ProviderID       string           `gorm:"size:36;index;not null" json:"provider_id"`
	Provider         ProviderInstance `gorm:"constraint:OnDelete:CASCADE;"`
	TokenEncrypted   []byte           `gorm:"type:bytea;not null" json:"-"`
	TokenFingerprint string           `gorm:"size:16" json:"token_fingerprint"`
	CreatedByUserID  string           `gorm:"size:36" json:"created_by"`
	CreatedAt        time.Time        `json:"created_at"`
	RevokedAt        *time.Time       `gorm:"index" json:"revoked_at,omitempty"`
	RevokedByUserID  string           `gorm:"size:36" json:"revoked_by,omitempty"`
}
