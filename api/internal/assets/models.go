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
	IsPrivate          bool       `gorm:"not null;default:false"`
	CreatedAt          time.Time
	CreatedByUserID    string     `gorm:"size:36"`
	ProviderUpdatedAt  *time.Time `gorm:"column:provider_updated_at;autoUpdateTime:false"`
}

// RepoCommit identifies a commit within a repository.
//
// AuthorName/Email/Date, Signed, and Message are captured by the runner
// via `git log -1 <sha>` on the clone (authoritative, no provider API).
// They stay nullable so rows from older runners survive unchanged; the
// UI's Commits tab filters out rows missing AuthorDate.
//
// Signed mirrors git's %G? verbatim: G=good, B=bad, U=good-unknown,
// X=good-expired, Y=good-expired-key, R=good-revoked-key, E=check-failed,
// N=no-signature.
type RepoCommit struct {
	ID          string     `gorm:"primaryKey;size:36"`
	RepoID      string     `gorm:"size:36;not null;uniqueIndex:ux_repo_commit"`
	Repo        Repo       `gorm:"constraint:OnUpdate:CASCADE,OnDelete:RESTRICT;"`
	CommitSHA   string     `gorm:"size:64;not null;uniqueIndex:ux_repo_commit"`
	Ref         string     `gorm:"size:255"`
	AuthorName  string     `gorm:"type:text"`
	AuthorEmail string     `gorm:"type:text"`
	AuthorDate  *time.Time
	Signed      string     `gorm:"size:1"`
	Message     string     `gorm:"type:text"`
	CreatedAt   time.Time
}

// ImageDigest identifies a container image by digest.
//
// SourceRepoID is a cached back-link to the repo the image claims to be
// built from, populated from the OCI org.opencontainers.image.source
// label at scan upload time. Indexed so the repo page's "images built
// from this repo" query stays cheap.
//
// SourceLabel is the raw URL from the same OCI label. Cached separately
// so the periodic reconciler can retry resolution (e.g. after a repo
// gets imported post-scan) without re-parsing the ~10KB labels blob on
// every tick. Also used by the UI to render an external-link fallback
// when the label doesn't match any repo in providers.
type ImageDigest struct {
	ID              string `gorm:"primaryKey;size:36"`
	Registry        string `gorm:"size:255;not null;uniqueIndex:ux_image_digest_identity"`
	Repository      string `gorm:"size:512;not null;uniqueIndex:ux_image_digest_identity"`
	Digest          string `gorm:"size:255;not null;uniqueIndex:ux_image_digest_identity"`
	SourceRepoID    string `gorm:"size:36;index"`
	SourceLabel     string `gorm:"size:512"`
	CreatedAt       time.Time
	CreatedByUserID string `gorm:"size:36"`

	// VerifiedSource gates ACL inheritance from SourceRepoID. The
	// OCI `org.opencontainers.image.source` label is self-reported by
	// the image producer, so an image claiming a private source repo
	// must not grant the reader access to that repo's cluster slot
	// unless the claim is cryptographically verified (cosign, sigstore,
	// or a signed attestation). Populated by the image scanner when a
	// valid signature chain is present; left false otherwise.
	VerifiedSource     bool       `gorm:"not null;default:false"`
	VerificationMethod string     `gorm:"size:32"`
	VerifiedAt         *time.Time
}
