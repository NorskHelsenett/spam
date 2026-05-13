package auth

import (
	"time"

	"gorm.io/datatypes"
)

// Session stores the server-side state for authenticated users.
//
// AccessTokenEnc / RefreshTokenEnc hold the OIDC tokens encrypted
// with the provider secrets key (AES-GCM). They power downstream-API
// calls made on behalf of the user (the ROR ACL provider today). The
// access token is refreshed on demand when AccessTokenExp is reached
// — the refresh rotates both tokens and updates the row in place, so
// the user never sees a re-login as long as the refresh token stays
// valid. Refresh tokens are only issued when `offline_access` is in
// OIDC_SCOPES; otherwise the access token is used until expiry, and
// then downstream calls degrade to no-grants until next login.
type Session struct {
	ID              string         `gorm:"primaryKey;size:64"`
	UserID          string         `gorm:"size:36;index"`
	Subject         string         `gorm:"index;size:255;not null"`
	Email           string         `gorm:"size:255"`
	Name            string         `gorm:"size:255"`
	Claims          datatypes.JSON `gorm:"type:jsonb"`
	AccessTokenEnc  []byte         `gorm:"type:bytea"`
	AccessTokenExp  time.Time
	RefreshTokenEnc []byte `gorm:"type:bytea"`
	CreatedAt       time.Time
	ExpiresAt       time.Time `gorm:"index"`
}
