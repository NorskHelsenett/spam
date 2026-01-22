package auth

import (
	"time"

	"gorm.io/datatypes"
)

// Session stores the server-side state for authenticated users.
type Session struct {
	ID        string         `gorm:"primaryKey;size:64"`
	UserID    string         `gorm:"size:36;index"`
	Subject   string         `gorm:"index;size:255;not null"`
	Email     string         `gorm:"size:255"`
	Name      string         `gorm:"size:255"`
	Claims    datatypes.JSON `gorm:"type:jsonb"`
	CreatedAt time.Time
	ExpiresAt time.Time `gorm:"index"`
}
