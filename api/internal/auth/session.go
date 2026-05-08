package auth

import (
	"time"

	"gorm.io/datatypes"
)

// Session stores the server-side state for authenticated users.
//
// AccessTokenEnc holds the EntraID access token encrypted with the
// provider secrets key (AES-GCM). It powers downstream-API calls made
// on behalf of the user — currently the ROR ACL probe / provider — so
// the user does not need to re-authenticate per outbound integration.
// Empty when no secrets key is configured at boot, in which case
// downstream-API calls fall back to service-token auth.
type Session struct {
	ID             string         `gorm:"primaryKey;size:64"`
	UserID         string         `gorm:"size:36;index"`
	Subject        string         `gorm:"index;size:255;not null"`
	Email          string         `gorm:"size:255"`
	Name           string         `gorm:"size:255"`
	Claims         datatypes.JSON `gorm:"type:jsonb"`
	AccessTokenEnc []byte         `gorm:"type:bytea"`
	AccessTokenExp time.Time
	CreatedAt      time.Time
	ExpiresAt      time.Time `gorm:"index"`
}
