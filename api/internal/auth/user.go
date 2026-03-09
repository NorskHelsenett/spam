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
	Email            string `gorm:"size:255;index"`
	Name             string `gorm:"size:255"`
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
