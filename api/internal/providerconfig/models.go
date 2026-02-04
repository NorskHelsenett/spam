package providerconfig

import "time"

// ProviderInstance represents a configured Git provider instance or org.
type ProviderInstance struct {
	ID              string    `gorm:"primaryKey;size:36" json:"id"`
	Type            string    `gorm:"size:16;not null;uniqueIndex:ux_provider_identity,priority:1" json:"type"`
	BaseURL         string    `gorm:"size:512;not null;uniqueIndex:ux_provider_identity,priority:2" json:"base_url"`
	OwnerPath       string    `gorm:"size:512;not null;default:'';uniqueIndex:ux_provider_identity,priority:3" json:"owner_path"`
	DisplayName     string    `gorm:"size:512;not null" json:"display_name"`
	Enabled         bool      `gorm:"not null;default:true" json:"enabled"`
	CreatedByUserID string    `gorm:"size:36" json:"created_by"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

// ProviderSecret stores encrypted PATs for provider instances.
type ProviderSecret struct {
	ID              string     `gorm:"primaryKey;size:36" json:"id"`
	ProviderID      string     `gorm:"size:36;index;not null" json:"provider_id"`
	Provider        ProviderInstance `gorm:"constraint:OnDelete:CASCADE;"`
	TokenEncrypted  []byte     `gorm:"type:bytea;not null" json:"-"`
	TokenFingerprint string    `gorm:"size:16" json:"token_fingerprint"`
	CreatedByUserID string     `gorm:"size:36" json:"created_by"`
	CreatedAt       time.Time  `json:"created_at"`
	RevokedAt       *time.Time `gorm:"index" json:"revoked_at,omitempty"`
}
