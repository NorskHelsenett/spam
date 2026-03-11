package assets

import "time"

// MaxRepoCacheAge is the maximum lifetime for a repo cache entry in kv_store.
// Entries older than this are considered stale even if the repo is unchanged.
const MaxRepoCacheAge = 7 * 24 * time.Hour

// RepoCacheData holds provider-fetched metadata for a repository stored in
// the kv_store table under the key "repo:cache:{repoID}".
type RepoCacheData struct {
	DetailsJSON      string    `json:"details_json"`
	ReadmeContent    string    `json:"readme_content"`
	CommitsJSON      string    `json:"commits_json"`
	ContributorsJSON string    `json:"contributors_json"`
	SyncedAt         time.Time `json:"synced_at"`
}

// RepoCacheEntry pairs a repo ID with its cached data, used when listing
// caches for an entire provider.
type RepoCacheEntry struct {
	RepoID string
	RepoCacheData
}

// Repo identifies a source code repository.
type Repo struct {
	ID                 string     `gorm:"primaryKey;size:36"`
	Provider           string     `gorm:"size:32;not null;default:manual"`
	Org                string     `gorm:"size:255;not null"`
	Slug               string     `gorm:"size:255;not null"`
	ExternalID         string     `gorm:"size:255;not null;default:''"`
	ProviderInstanceID string     `gorm:"size:36;not null;index"`
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
