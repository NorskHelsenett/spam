package providers

import (
	"context"
	"errors"
)

// Common errors returned by provider clients.
var (
	ErrRateLimited     = errors.New("rate limited")
	ErrNotFound        = errors.New("not found")
	ErrUnauthorized    = errors.New("unauthorized")
	ErrInvalidResponse = errors.New("invalid response")
)

// Client defines the interface for Git provider API operations.
// All methods support unauthenticated access for public resources.
type Client interface {
	// ListPublicRepos lists public repositories for a user or organization.
	// For GitHub: owner can be a user or organization login.
	// For GitLab: owner should be a group path.
	ListPublicRepos(ctx context.Context, owner string, opts ListOptions) ([]RepoData, PageInfo, error)

	// ListPublicOrgs lists public organizations/groups.
	// For GitHub: lists orgs for a username.
	// For GitLab: lists subgroups of a group, or root groups if empty.
	ListPublicOrgs(ctx context.Context, username string, opts ListOptions) ([]OrgData, PageInfo, error)

	// BaseURL returns the base URL of the provider API.
	BaseURL() string

	// ProviderType returns the type of provider (github, gitlab, gitea, forgejo).
	ProviderType() string
}

// GitLabClient extends the base Client with GitLab-specific methods.
type GitLabClient interface {
	Client

	// ListPublicGroups lists public groups.
	// If parentPath is empty, lists root-level groups.
	// Otherwise, lists subgroups of the specified group.
	ListPublicGroups(ctx context.Context, parentPath string, opts ListOptions) ([]GroupData, PageInfo, error)

	// ListPublicProjects lists public projects for a group.
	ListPublicProjects(ctx context.Context, groupPath string, opts ListOptions) ([]RepoData, PageInfo, error)
}
