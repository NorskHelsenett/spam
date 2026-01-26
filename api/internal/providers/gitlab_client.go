package providers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	defaultGitLabBaseURL = "https://gitlab.com/api/v4"
)

// GitLabClientImpl implements the GitLabClient interface.
type GitLabClientImpl struct {
	baseURL    string
	httpClient *http.Client
	token      string // Optional: for authenticated requests (future use)
}

// NewGitLabClient creates a new GitLab client.
// baseURL can be empty for gitlab.com or set for self-hosted instances.
func NewGitLabClient(baseURL string, token string) *GitLabClientImpl {
	if baseURL == "" {
		baseURL = defaultGitLabBaseURL
	}
	baseURL = strings.TrimSuffix(baseURL, "/")
	// Ensure /api/v4 suffix for self-hosted
	if !strings.HasSuffix(baseURL, "/api/v4") && !strings.Contains(baseURL, "gitlab.com") {
		baseURL = baseURL + "/api/v4"
	}

	return &GitLabClientImpl{
		baseURL: baseURL,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		token: token,
	}
}

func (c *GitLabClientImpl) BaseURL() string {
	return c.baseURL
}

func (c *GitLabClientImpl) ProviderType() string {
	return "gitlab"
}

// gitLabProject represents a project from the GitLab API.
type gitLabProject struct {
	ID                int64     `json:"id"`
	Name              string    `json:"name"`
	Path              string    `json:"path"`
	PathWithNamespace string    `json:"path_with_namespace"`
	Description       string    `json:"description"`
	WebURL            string    `json:"web_url"`
	DefaultBranch     string    `json:"default_branch"`
	Visibility        string    `json:"visibility"`
	Archived          bool      `json:"archived"`
	ForkedFromProject *struct{} `json:"forked_from_project"` // Non-nil if forked
	Topics            []string  `json:"topics"`
	CreatedAt         time.Time `json:"created_at"`
	LastActivityAt    time.Time `json:"last_activity_at"`
}

// gitLabGroup represents a group from the GitLab API.
type gitLabGroup struct {
	ID          int64  `json:"id"`
	Name        string `json:"name"`
	Path        string `json:"path"`
	FullPath    string `json:"full_path"`
	Description string `json:"description"`
	WebURL      string `json:"web_url"`
	ParentID    *int64 `json:"parent_id"`
	Visibility  string `json:"visibility"`
}

// ListPublicRepos implements Client.ListPublicRepos for GitLab.
// For GitLab, owner is treated as a group path.
func (c *GitLabClientImpl) ListPublicRepos(ctx context.Context, owner string, opts ListOptions) ([]RepoData, PageInfo, error) {
	return c.ListPublicProjects(ctx, owner, opts)
}

// ListPublicOrgs implements Client.ListPublicOrgs for GitLab.
// Returns subgroups of the given group (or root groups if empty).
func (c *GitLabClientImpl) ListPublicOrgs(ctx context.Context, groupPath string, opts ListOptions) ([]OrgData, PageInfo, error) {
	groups, pageInfo, err := c.ListPublicGroups(ctx, groupPath, opts)
	if err != nil {
		return nil, PageInfo{}, err
	}

	// Convert GroupData to OrgData for interface compatibility
	orgs := make([]OrgData, len(groups))
	for i, g := range groups {
		orgs[i] = OrgData{
			ExternalID:  g.ExternalID,
			Login:       g.Path,
			Name:        g.Name,
			Description: g.Description,
			HTMLURL:     g.HTMLURL,
		}
	}

	return orgs, pageInfo, nil
}

// ListPublicProjects lists public projects for a group, or all public projects if groupPath is empty.
func (c *GitLabClientImpl) ListPublicProjects(ctx context.Context, groupPath string, opts ListOptions) ([]RepoData, PageInfo, error) {
	if opts.PageSize <= 0 {
		opts.PageSize = defaultPageSize
	}
	if opts.PageSize > maxPageSize {
		opts.PageSize = maxPageSize
	}
	if opts.Page <= 0 {
		opts.Page = 1
	}

	var urlStr string
	if groupPath != "" {
		// URL-encode the group path (GitLab uses / in group paths)
		encodedPath := url.PathEscape(groupPath)
		urlStr = fmt.Sprintf("%s/groups/%s/projects?visibility=public&per_page=%d&page=%d&include_subgroups=%v&order_by=last_activity_at&sort=desc",
			c.baseURL, encodedPath, opts.PageSize, opts.Page, opts.IncludeSubgroups)
	} else {
		// List all public projects on the instance
		urlStr = fmt.Sprintf("%s/projects?visibility=public&per_page=%d&page=%d&order_by=last_activity_at&sort=desc",
			c.baseURL, opts.PageSize, opts.Page)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, urlStr, nil)
	if err != nil {
		return nil, PageInfo{}, err
	}

	if c.token != "" {
		req.Header.Set("PRIVATE-TOKEN", c.token)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, PageInfo{}, err
	}
	defer resp.Body.Close()

	if err := c.checkResponse(resp); err != nil {
		return nil, PageInfo{}, err
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, PageInfo{}, err
	}

	var glProjects []gitLabProject
	if err := json.Unmarshal(body, &glProjects); err != nil {
		return nil, PageInfo{}, fmt.Errorf("%w: %v", ErrInvalidResponse, err)
	}

	repos := make([]RepoData, len(glProjects))
	for i, p := range glProjects {
		repos[i] = RepoData{
			ExternalID:    strconv.FormatInt(p.ID, 10),
			Name:          p.Name,
			FullPath:      p.PathWithNamespace,
			Description:   p.Description,
			HTMLURL:       p.WebURL,
			DefaultBranch: p.DefaultBranch,
			IsPrivate:     p.Visibility != "public",
			IsArchived:    p.Archived,
			IsFork:        p.ForkedFromProject != nil,
			Topics:        p.Topics,
			CreatedAt:     p.CreatedAt,
			UpdatedAt:     p.LastActivityAt,
			PushedAt:      p.LastActivityAt, // GitLab doesn't separate pushed_at
		}
	}

	pageInfo := c.parsePageInfo(resp)
	return repos, pageInfo, nil
}

// ListPublicGroups lists public groups.
func (c *GitLabClientImpl) ListPublicGroups(ctx context.Context, parentPath string, opts ListOptions) ([]GroupData, PageInfo, error) {
	if opts.PageSize <= 0 {
		opts.PageSize = defaultPageSize
	}
	if opts.PageSize > maxPageSize {
		opts.PageSize = maxPageSize
	}
	if opts.Page <= 0 {
		opts.Page = 1
	}

	var urlStr string
	if parentPath != "" {
		// List subgroups of a specific group
		encodedPath := url.PathEscape(parentPath)
		urlStr = fmt.Sprintf("%s/groups/%s/subgroups?per_page=%d&page=%d&all_available=true",
			c.baseURL, encodedPath, opts.PageSize, opts.Page)
	} else {
		// List top-level public groups
		urlStr = fmt.Sprintf("%s/groups?visibility=public&per_page=%d&page=%d&top_level_only=true&order_by=name",
			c.baseURL, opts.PageSize, opts.Page)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, urlStr, nil)
	if err != nil {
		return nil, PageInfo{}, err
	}

	if c.token != "" {
		req.Header.Set("PRIVATE-TOKEN", c.token)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, PageInfo{}, err
	}
	defer resp.Body.Close()

	if err := c.checkResponse(resp); err != nil {
		return nil, PageInfo{}, err
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, PageInfo{}, err
	}

	var glGroups []gitLabGroup
	if err := json.Unmarshal(body, &glGroups); err != nil {
		return nil, PageInfo{}, fmt.Errorf("%w: %v", ErrInvalidResponse, err)
	}

	groups := make([]GroupData, len(glGroups))
	for i, g := range glGroups {
		groups[i] = GroupData{
			ExternalID:  strconv.FormatInt(g.ID, 10),
			Name:        g.Name,
			Path:        g.Path,
			FullPath:    g.FullPath,
			Description: g.Description,
			HTMLURL:     g.WebURL,
			Visibility:  g.Visibility,
		}
		if g.ParentID != nil {
			groups[i].ParentID = strconv.FormatInt(*g.ParentID, 10)
		}
	}

	pageInfo := c.parsePageInfo(resp)
	return groups, pageInfo, nil
}

func (c *GitLabClientImpl) checkResponse(resp *http.Response) error {
	switch resp.StatusCode {
	case http.StatusOK:
		return nil
	case http.StatusNotFound:
		return ErrNotFound
	case http.StatusUnauthorized:
		return ErrUnauthorized
	case http.StatusForbidden:
		return ErrUnauthorized
	case http.StatusTooManyRequests:
		return ErrRateLimited
	default:
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(body))
	}
}

// parsePageInfo extracts pagination info from GitLab headers.
func (c *GitLabClientImpl) parsePageInfo(resp *http.Response) PageInfo {
	info := PageInfo{}

	// GitLab uses X-Page, X-Next-Page, X-Total headers
	if nextPage := resp.Header.Get("X-Next-Page"); nextPage != "" {
		if page, err := strconv.Atoi(nextPage); err == nil && page > 0 {
			info.NextPage = page
			info.HasNextPage = true
		}
	}

	if total := resp.Header.Get("X-Total"); total != "" {
		if count, err := strconv.Atoi(total); err == nil {
			info.TotalCount = count
		}
	}

	return info
}
