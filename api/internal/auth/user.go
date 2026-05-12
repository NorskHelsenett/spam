package auth

import "time"

const (
	GroupDefault      = "default"
	GroupAdmin        = "admin"
	GroupGlobalReader = "global_reader"
)

// User represents an authenticated identity from OIDC.
type User struct {
	ID               string `gorm:"primaryKey;size:36"`
	Subject          string `gorm:"size:255;uniqueIndex;not null"`
	Email            string `gorm:"size:255;uniqueIndex"`
	Name             string `gorm:"size:255"`
	// Picture stores a self-contained data URL ("data:image/jpeg;base64,...")
	// fetched from Microsoft Graph at login. Falls back to Gravatar at the
	// API boundary when empty.
	Picture          string `gorm:"type:text"`
	// EntraGroups holds a JSON-encoded array of EntraID group display names
	// the user belongs to, fetched from Microsoft Graph at login. Empty
	// string means "not fetched / unavailable" (e.g. token lacks the scope).
	EntraGroups      string `gorm:"type:text"`
	ApprovedAt       *time.Time
	ApprovedByUserID *string    `gorm:"size:36"`
	HiddenAt         *time.Time
	LastLoginAt      *time.Time `gorm:"index"`
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

// Group defines a role-like collection of permissions.
type Group struct {
	ID        string `gorm:"primaryKey;size:36"`
	Slug      string `gorm:"size:64;uniqueIndex;not null"`
	Name      string `gorm:"size:128;not null"`
	CreatedAt time.Time
}

// UserGroup links users to groups.
type UserGroup struct {
	UserID    string `gorm:"primaryKey;size:36"`
	GroupID   string `gorm:"primaryKey;size:36"`
	CreatedAt time.Time
}
