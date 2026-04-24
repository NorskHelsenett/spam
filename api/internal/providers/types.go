package providers

import "time"

// RepoData represents a repository from any Git provider.
type RepoData struct {
	ExternalID    string    `json:"external_id"`
	Name          string    `json:"name"`
	FullPath      string    `json:"full_path"`
	Description   string    `json:"description"`
	HTMLURL       string    `json:"html_url"`
	DefaultBranch string    `json:"default_branch"`
	Languages     []string  `json:"languages"`
	IsPrivate     bool      `json:"is_private"`
	IsArchived    bool      `json:"is_archived"`
	IsDisabled    bool      `json:"is_disabled"`
	IsFork        bool      `json:"is_fork"`
	IsEmpty       bool      `json:"is_empty"`
	Topics        []string  `json:"topics"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
	PushedAt      time.Time `json:"pushed_at"`
}

// OrgData represents an organization from GitHub/Gitea.
type OrgData struct {
	ExternalID  string `json:"external_id"`
	Login       string `json:"login"`
	Name        string `json:"name"`
	Description string `json:"description"`
	HTMLURL     string `json:"html_url"`
	AvatarURL   string `json:"avatar_url"`
}

// GroupData represents a group from GitLab.
type GroupData struct {
	ExternalID  string `json:"external_id"`
	Name        string `json:"name"`
	Path        string `json:"path"`
	FullPath    string `json:"full_path"`
	Description string `json:"description"`
	HTMLURL     string `json:"html_url"`
	ParentID    string `json:"parent_id,omitempty"`
	Visibility  string `json:"visibility"`
}

// ListOptions contains pagination and filtering options for API requests.
type ListOptions struct {
	Page     int
	PageSize int
	// For GitLab: include subgroups in project listing
	IncludeSubgroups bool
}

// PageInfo contains pagination metadata from API responses.
type PageInfo struct {
	// TotalCount is the total number of items (if provided by the API)
	TotalCount int
	// NextPage is the page number to fetch next, or 0 if no more pages
	NextPage int
	// HasNextPage indicates if there are more pages
	HasNextPage bool
}

// RepoStats represents repository statistics.
type RepoStats struct {
	Stars        int `json:"stars"`
	Forks        int `json:"forks"`
	Watchers     int `json:"watchers"`
	OpenIssues   int `json:"open_issues"`
	Commits      int `json:"commits"`
	Branches     int `json:"branches"`
	Releases     int `json:"releases"`
	Contributors int `json:"contributors"`
}

// RepoDetails represents detailed repository information.
type RepoDetails struct {
	RepoData
	Stats   RepoStats `json:"stats"`
	License string    `json:"license"`
	Size    int64     `json:"size"` // in KB
}

// CommitImage identifies one image built from a commit with enough
// detail for the UI to render a docker-pullable reference — copy
// `{registry}/{repository}@{digest}` and paste into docker pull/inspect.
type CommitImage struct {
	Registry   string `json:"registry"`
	Repository string `json:"repository"`
	Digest     string `json:"digest"`
}

// CommitInfo represents a single commit from a git provider.
//
// Signed is empty for provider-API-sourced commits. Runner-sourced
// commits in repo_commits carry git's %G? output (G/B/U/X/Y/R/E/N)
// so the UI can render signature state.
//
// ImageCount / LivePodCount / LiveClusterCount are populated only by
// the DB-backed path (loadCommitsFromRepoCommits) — they drive the
// three-icon "signed → built → live" status cluster on each commit
// row. Zero on provider-API-sourced commits. Images carries the
// concrete list (registry/repo/digest) for the commit-detail dialog.
type CommitInfo struct {
	SHA              string        `json:"sha"`
	Message          string        `json:"message"`
	AuthorName       string        `json:"author_name"`
	AuthorEmail      string        `json:"author_email"`
	AuthorDate       time.Time     `json:"author_date"`
	AuthorLogin      string        `json:"author_login,omitempty"`
	AuthorAvatar     string        `json:"author_avatar,omitempty"`
	CommitURL        string        `json:"commit_url,omitempty"`
	Signed           string        `json:"signed,omitempty"`
	ImageCount       int           `json:"image_count"`
	LivePodCount     int           `json:"live_pod_count"`
	LiveClusterCount int           `json:"live_cluster_count"`
	Images           []CommitImage `json:"images,omitempty"`
}

// ContributorInfo represents a contributor to a repository.
type ContributorInfo struct {
	Login         string `json:"login,omitempty"`
	Name          string `json:"name,omitempty"`
	Email         string `json:"email,omitempty"`
	AvatarURL     string `json:"avatar_url,omitempty"`
	ProfileURL    string `json:"profile_url,omitempty"`
	Contributions int    `json:"contributions"`
}
