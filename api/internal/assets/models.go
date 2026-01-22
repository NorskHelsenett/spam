package assets

import "time"

// Repo identifies a source code repository.
type Repo struct {
	ID              string `gorm:"primaryKey;size:36"`
	Provider        string `gorm:"size:32;not null;default:manual;uniqueIndex:ux_repo_identity"`
	Org             string `gorm:"size:255;not null;uniqueIndex:ux_repo_identity"`
	Slug            string `gorm:"size:255;not null;uniqueIndex:ux_repo_identity"`
	CreatedAt       time.Time
	CreatedByUserID string `gorm:"size:36"`
}

// RepoCommit identifies a commit within a repository.
type RepoCommit struct {
	ID        string `gorm:"primaryKey;size:36"`
	RepoID    string `gorm:"size:36;not null;uniqueIndex:ux_repo_commit"`
	CommitSHA string `gorm:"size:64;not null;uniqueIndex:ux_repo_commit"`
	Ref       string `gorm:"size:255"`
	CreatedAt time.Time
}
