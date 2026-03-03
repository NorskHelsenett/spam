package assets

import "time"

// Repo identifies a source code repository.
type Repo struct {
	ID                 string     `gorm:"primaryKey;size:36"`
	Provider           string     `gorm:"size:32;not null;default:manual"`
	Org                string     `gorm:"size:255;not null"`
	Slug               string     `gorm:"size:255;not null"`
	ProviderInstanceID *string    `gorm:"size:36;index"`
	CreatedAt          time.Time
	CreatedByUserID    string     `gorm:"size:36"`
	ProviderUpdatedAt  *time.Time `gorm:"column:provider_updated_at;autoUpdateTime:false"`
}

// RepoCommit identifies a commit within a repository.
type RepoCommit struct {
	ID        string `gorm:"primaryKey;size:36"`
	RepoID    string `gorm:"size:36;not null;uniqueIndex:ux_repo_commit"`
	Repo      Repo   `gorm:"constraint:OnUpdate:CASCADE,OnDelete:RESTRICT;"`
	CommitSHA string `gorm:"size:64;not null;uniqueIndex:ux_repo_commit"`
	Ref       string `gorm:"size:255"`
	CreatedAt time.Time
}

// ImageDigest identifies a container image by digest.
type ImageDigest struct {
	ID              string `gorm:"primaryKey;size:36"`
	Registry        string `gorm:"size:255;not null;uniqueIndex:ux_image_digest_identity"`
	Repository      string `gorm:"size:512;not null;uniqueIndex:ux_image_digest_identity"`
	Digest          string `gorm:"size:255;not null;uniqueIndex:ux_image_digest_identity"`
	CreatedAt       time.Time
	CreatedByUserID string `gorm:"size:36"`
}
