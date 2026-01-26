package providers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	defaultGitHubBaseURL = "https://api.github.com"
	defaultPageSize      = 30
	maxPageSize          = 100
)

// GitHubClientImpl implements the Client interface for GitHub.
type GitHubClientImpl struct {
	baseURL    string
	httpClient *http.Client
	token      string // Optional: for authenticated requests (future use)
}

// NewGitHubClient creates a new GitHub client.
// baseURL can be empty for github.com or set for GitHub Enterprise.
func NewGitHubClient(baseURL string, token string) *GitHubClientImpl {
	if baseURL == "" {
		baseURL = defaultGitHubBaseURL
	}
	baseURL = strings.TrimSuffix(baseURL, "/")

	return &GitHubClientImpl{
		baseURL: baseURL,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		token: token,
	}
}

func (c *GitHubClientImpl) BaseURL() string {
	return c.baseURL
}

func (c *GitHubClientImpl) ProviderType() string {
	return "github"
}

// gitHubRepo represents a repository from the GitHub API.
type gitHubRepo struct {
	ID            int64     `json:"id"`
	Name          string    `json:"name"`
	FullName      string    `json:"full_name"`
	Description   string    `json:"description"`
	HTMLURL       string    `json:"html_url"`
	DefaultBranch string    `json:"default_branch"`
	Language      string    `json:"language"`
	Private       bool      `json:"private"`
	Archived      bool      `json:"archived"`
	Fork          bool      `json:"fork"`
	Topics        []string  `json:"topics"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
	PushedAt      time.Time `json:"pushed_at"`
}

// gitHubOrg represents an organization from the GitHub API.
type gitHubOrg struct {
	ID          int64  `json:"id"`
	Login       string `json:"login"`
	Name        string `json:"name"`
	Description string `json:"description"`
	HTMLURL     string `json:"html_url"`
	AvatarURL   string `json:"avatar_url"`
}

// ListPublicRepos lists public repositories for a user or organization.
func (c *GitHubClientImpl) ListPublicRepos(ctx context.Context, owner string, opts ListOptions) ([]RepoData, PageInfo, error) {
	if opts.PageSize <= 0 {
		opts.PageSize = defaultPageSize
	}
	if opts.PageSize > maxPageSize {
		opts.PageSize = maxPageSize
	}
	if opts.Page <= 0 {
		opts.Page = 1
	}

	// First, try as an org, then as a user
	repos, pageInfo, err := c.listOrgRepos(ctx, owner, opts)
	if err != nil {
		// If org endpoint fails (404), try user endpoint
		if err == ErrNotFound {
			return c.listUserRepos(ctx, owner, opts)
		}
		return nil, PageInfo{}, err
	}
	return repos, pageInfo, nil
}

func (c *GitHubClientImpl) listOrgRepos(ctx context.Context, org string, opts ListOptions) ([]RepoData, PageInfo, error) {
	url := fmt.Sprintf("%s/orgs/%s/repos?type=public&per_page=%d&page=%d",
		c.baseURL, org, opts.PageSize, opts.Page)
	return c.fetchRepos(ctx, url, opts.PageSize)
}

func (c *GitHubClientImpl) listUserRepos(ctx context.Context, username string, opts ListOptions) ([]RepoData, PageInfo, error) {
	url := fmt.Sprintf("%s/users/%s/repos?type=public&per_page=%d&page=%d",
		c.baseURL, username, opts.PageSize, opts.Page)
	return c.fetchRepos(ctx, url, opts.PageSize)
}

func (c *GitHubClientImpl) fetchRepos(ctx context.Context, url string, pageSize int) ([]RepoData, PageInfo, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, PageInfo{}, err
	}

	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
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

	var ghRepos []gitHubRepo
	if err := json.Unmarshal(body, &ghRepos); err != nil {
		return nil, PageInfo{}, fmt.Errorf("%w: %v", ErrInvalidResponse, err)
	}

	repos := make([]RepoData, len(ghRepos))
	for i, r := range ghRepos {
		repos[i] = RepoData{
			ExternalID:    strconv.FormatInt(r.ID, 10),
			Name:          r.Name,
			FullPath:      r.FullName,
			Description:   r.Description,
			HTMLURL:       r.HTMLURL,
			DefaultBranch: r.DefaultBranch,
			Language:      r.Language,
			IsPrivate:     r.Private,
			IsArchived:    r.Archived,
			IsFork:        r.Fork,
			Topics:        r.Topics,
			CreatedAt:     r.CreatedAt,
			UpdatedAt:     r.UpdatedAt,
			PushedAt:      r.PushedAt,
		}
	}

	pageInfo := c.parsePageInfo(resp, pageSize)
	return repos, pageInfo, nil
}

// ListPublicOrgs lists public organizations for a user.
func (c *GitHubClientImpl) ListPublicOrgs(ctx context.Context, username string, opts ListOptions) ([]OrgData, PageInfo, error) {
	if opts.PageSize <= 0 {
		opts.PageSize = defaultPageSize
	}
	if opts.PageSize > maxPageSize {
		opts.PageSize = maxPageSize
	}
	if opts.Page <= 0 {
		opts.Page = 1
	}

	url := fmt.Sprintf("%s/users/%s/orgs?per_page=%d&page=%d",
		c.baseURL, username, opts.PageSize, opts.Page)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, PageInfo{}, err
	}

	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
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

	var ghOrgs []gitHubOrg
	if err := json.Unmarshal(body, &ghOrgs); err != nil {
		return nil, PageInfo{}, fmt.Errorf("%w: %v", ErrInvalidResponse, err)
	}

	orgs := make([]OrgData, len(ghOrgs))
	for i, o := range ghOrgs {
		orgs[i] = OrgData{
			ExternalID:  strconv.FormatInt(o.ID, 10),
			Login:       o.Login,
			Name:        o.Name,
			Description: o.Description,
			HTMLURL:     o.HTMLURL,
			AvatarURL:   o.AvatarURL,
		}
	}

	pageInfo := c.parsePageInfo(resp, opts.PageSize)
	return orgs, pageInfo, nil
}

func (c *GitHubClientImpl) checkResponse(resp *http.Response) error {
	switch resp.StatusCode {
	case http.StatusOK:
		return nil
	case http.StatusNotFound:
		return ErrNotFound
	case http.StatusUnauthorized:
		return ErrUnauthorized
	case http.StatusForbidden:
		// Check if rate limited
		if resp.Header.Get("X-RateLimit-Remaining") == "0" {
			return ErrRateLimited
		}
		return ErrUnauthorized
	case http.StatusTooManyRequests:
		return ErrRateLimited
	default:
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(body))
	}
}

// parsePageInfo extracts pagination info from GitHub's Link header.
// GitHub Link header format: <url>; rel="next", <url>; rel="last"
func (c *GitHubClientImpl) parsePageInfo(resp *http.Response, pageSize int) PageInfo {
	info := PageInfo{}

	// Parse Link header for pagination
	linkHeader := resp.Header.Get("Link")
	if linkHeader == "" {
		return info
	}

	var lastPage int
	links := strings.Split(linkHeader, ",")
	for _, link := range links {
		parts := strings.Split(strings.TrimSpace(link), ";")
		if len(parts) < 2 {
			continue
		}

		urlPart := strings.Trim(strings.TrimSpace(parts[0]), "<>")
		rel := strings.TrimSpace(parts[1])

		pageNum := extractPageParam(urlPart)
		if pageNum <= 0 {
			continue
		}

		switch rel {
		case `rel="next"`:
			info.NextPage = pageNum
			info.HasNextPage = true
		case `rel="last"`:
			lastPage = pageNum
		}
	}

	// Estimate total count from last page
	if lastPage > 0 && pageSize > 0 {
		info.TotalCount = lastPage * pageSize
	}

	return info
}

// extractPageParam extracts the page parameter from a URL string.
func extractPageParam(urlStr string) int {
	idx := strings.Index(urlStr, "page=")
	if idx < 0 {
		return 0
	}
	pageStr := urlStr[idx+5:]
	if endIdx := strings.IndexAny(pageStr, "&>"); endIdx > 0 {
		pageStr = pageStr[:endIdx]
	}
	page, err := strconv.Atoi(pageStr)
	if err != nil {
		return 0
	}
	return page
}
