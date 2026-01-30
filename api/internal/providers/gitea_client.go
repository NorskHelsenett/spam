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

// GiteaClientImpl implements the Client interface for Gitea/Forgejo.
type GiteaClientImpl struct {
	baseURL    string
	httpClient *http.Client
	token      string
}

// NewGiteaClient creates a new Gitea/Forgejo client.
func NewGiteaClient(baseURL string, token string) *GiteaClientImpl {
	baseURL = strings.TrimSuffix(baseURL, "/")
	// Ensure /api/v1 suffix
	if !strings.HasSuffix(baseURL, "/api/v1") {
		baseURL = baseURL + "/api/v1"
	}

	return &GiteaClientImpl{
		baseURL: baseURL,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		token: token,
	}
}

func (c *GiteaClientImpl) BaseURL() string {
	return c.baseURL
}

func (c *GiteaClientImpl) ProviderType() string {
	return "gitea"
}

// giteaRepo represents a repository from the Gitea API.
type giteaRepo struct {
	ID            int64     `json:"id"`
	Name          string    `json:"name"`
	FullName      string    `json:"full_name"`
	Description   string    `json:"description"`
	HTMLURL       string    `json:"html_url"`
	DefaultBranch string    `json:"default_branch"`
	Private       bool      `json:"private"`
	Fork          bool      `json:"fork"`
	Archived      bool      `json:"archived"`
	Language      string    `json:"language"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// giteaOrg represents an organization from the Gitea API.
type giteaOrg struct {
	ID          int64  `json:"id"`
	Name        string `json:"name"`
	FullName    string `json:"full_name"`
	Description string `json:"description"`
	Website     string `json:"website"`
	AvatarURL   string `json:"avatar_url"`
}

// ListPublicRepos lists public repositories for an organization.
func (c *GiteaClientImpl) ListPublicRepos(ctx context.Context, owner string, opts ListOptions) ([]RepoData, PageInfo, error) {
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
	if owner != "" {
		urlStr = fmt.Sprintf("%s/orgs/%s/repos?page=%d&limit=%d",
			c.baseURL, url.PathEscape(owner), opts.Page, opts.PageSize)
	} else {
		// List all public repos
		urlStr = fmt.Sprintf("%s/repos/search?page=%d&limit=%d&sort=updated&order=desc",
			c.baseURL, opts.Page, opts.PageSize)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, urlStr, nil)
	if err != nil {
		return nil, PageInfo{}, err
	}

	if c.token != "" {
		req.Header.Set("Authorization", "token "+c.token)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, PageInfo{}, err
	}
	defer resp.Body.Close()

	if err := c.checkResponse(resp); err != nil {
		// If org not found, try as user
		if err == ErrNotFound && owner != "" {
			return c.listUserRepos(ctx, owner, opts)
		}
		return nil, PageInfo{}, err
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, PageInfo{}, err
	}

	// Handle search response vs direct list
	var giteaRepos []giteaRepo
	if owner == "" {
		// Search endpoint returns { data: [...], ok: true }
		var searchResp struct {
			Data []giteaRepo `json:"data"`
			OK   bool        `json:"ok"`
		}
		if err := json.Unmarshal(body, &searchResp); err != nil {
			return nil, PageInfo{}, fmt.Errorf("%w: %v", ErrInvalidResponse, err)
		}
		giteaRepos = searchResp.Data
	} else {
		if err := json.Unmarshal(body, &giteaRepos); err != nil {
			return nil, PageInfo{}, fmt.Errorf("%w: %v", ErrInvalidResponse, err)
		}
	}

	repos := make([]RepoData, len(giteaRepos))
	for i, r := range giteaRepos {
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
			CreatedAt:     r.CreatedAt,
			UpdatedAt:     r.UpdatedAt,
			PushedAt:      r.UpdatedAt,
		}
	}

	pageInfo := c.parsePageInfo(resp, opts.PageSize, len(repos))
	return repos, pageInfo, nil
}

func (c *GiteaClientImpl) listUserRepos(ctx context.Context, username string, opts ListOptions) ([]RepoData, PageInfo, error) {
	urlStr := fmt.Sprintf("%s/users/%s/repos?page=%d&limit=%d",
		c.baseURL, url.PathEscape(username), opts.Page, opts.PageSize)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, urlStr, nil)
	if err != nil {
		return nil, PageInfo{}, err
	}

	if c.token != "" {
		req.Header.Set("Authorization", "token "+c.token)
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

	var giteaRepos []giteaRepo
	if err := json.Unmarshal(body, &giteaRepos); err != nil {
		return nil, PageInfo{}, fmt.Errorf("%w: %v", ErrInvalidResponse, err)
	}

	repos := make([]RepoData, len(giteaRepos))
	for i, r := range giteaRepos {
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
			CreatedAt:     r.CreatedAt,
			UpdatedAt:     r.UpdatedAt,
			PushedAt:      r.UpdatedAt,
		}
	}

	pageInfo := c.parsePageInfo(resp, opts.PageSize, len(repos))
	return repos, pageInfo, nil
}

// ListPublicOrgs lists public organizations.
func (c *GiteaClientImpl) ListPublicOrgs(ctx context.Context, _ string, opts ListOptions) ([]OrgData, PageInfo, error) {
	if opts.PageSize <= 0 {
		opts.PageSize = defaultPageSize
	}
	if opts.PageSize > maxPageSize {
		opts.PageSize = maxPageSize
	}
	if opts.Page <= 0 {
		opts.Page = 1
	}

	urlStr := fmt.Sprintf("%s/orgs?page=%d&limit=%d",
		c.baseURL, opts.Page, opts.PageSize)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, urlStr, nil)
	if err != nil {
		return nil, PageInfo{}, err
	}

	if c.token != "" {
		req.Header.Set("Authorization", "token "+c.token)
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

	var giteaOrgs []giteaOrg
	if err := json.Unmarshal(body, &giteaOrgs); err != nil {
		return nil, PageInfo{}, fmt.Errorf("%w: %v", ErrInvalidResponse, err)
	}

	orgs := make([]OrgData, len(giteaOrgs))
	for i, o := range giteaOrgs {
		orgs[i] = OrgData{
			ExternalID:  strconv.FormatInt(o.ID, 10),
			Login:       o.Name,
			Name:        o.FullName,
			Description: o.Description,
			AvatarURL:   o.AvatarURL,
		}
	}

	pageInfo := c.parsePageInfo(resp, opts.PageSize, len(orgs))
	return orgs, pageInfo, nil
}

func (c *GiteaClientImpl) checkResponse(resp *http.Response) error {
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

func (c *GiteaClientImpl) parsePageInfo(resp *http.Response, pageSize int, resultCount int) PageInfo {
	info := PageInfo{}

	// Gitea uses Link header similar to GitHub, or X-Total-Count
	if total := resp.Header.Get("X-Total-Count"); total != "" {
		if count, err := strconv.Atoi(total); err == nil {
			info.TotalCount = count
		}
	}

	// Check if there's a next page based on result count
	if resultCount >= pageSize {
		info.HasNextPage = true
		// Parse current page from request URL or assume increment
		if page := resp.Request.URL.Query().Get("page"); page != "" {
			if p, err := strconv.Atoi(page); err == nil {
				info.NextPage = p + 1
			}
		}
	}

	return info
}

// giteaRepoDetails represents detailed repo info from Gitea API.
type giteaRepoDetails struct {
	giteaRepo
	StarsCount      int   `json:"stars_count"`
	ForksCount      int   `json:"forks_count"`
	WatchersCount   int   `json:"watchers_count"`
	OpenIssuesCount int   `json:"open_issues_count"`
	Size            int64 `json:"size"`
}

// GetRepoDetails fetches detailed information about a repository.
func (c *GiteaClientImpl) GetRepoDetails(ctx context.Context, owner, repo string) (*RepoDetails, error) {
	urlStr := fmt.Sprintf("%s/repos/%s/%s", c.baseURL, url.PathEscape(owner), url.PathEscape(repo))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, urlStr, nil)
	if err != nil {
		return nil, err
	}

	if c.token != "" {
		req.Header.Set("Authorization", "token "+c.token)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if err := c.checkResponse(resp); err != nil {
		return nil, err
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var gRepo giteaRepoDetails
	if err := json.Unmarshal(body, &gRepo); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidResponse, err)
	}

	stats := RepoStats{
		Stars:      gRepo.StarsCount,
		Forks:      gRepo.ForksCount,
		Watchers:   gRepo.WatchersCount,
		OpenIssues: gRepo.OpenIssuesCount,
	}

	// Fetch additional counts
	stats.Commits = c.getCommitCount(ctx, owner, repo)
	stats.Branches = c.getBranchCount(ctx, owner, repo)
	stats.Releases = c.getReleaseCount(ctx, owner, repo)

	return &RepoDetails{
		RepoData: RepoData{
			ExternalID:    strconv.FormatInt(gRepo.ID, 10),
			Name:          gRepo.Name,
			FullPath:      gRepo.FullName,
			Description:   gRepo.Description,
			HTMLURL:       gRepo.HTMLURL,
			DefaultBranch: gRepo.DefaultBranch,
			Language:      gRepo.Language,
			IsPrivate:     gRepo.Private,
			IsArchived:    gRepo.Archived,
			IsFork:        gRepo.Fork,
			CreatedAt:     gRepo.CreatedAt,
			UpdatedAt:     gRepo.UpdatedAt,
			PushedAt:      gRepo.UpdatedAt,
		},
		Stats: stats,
		Size:  gRepo.Size,
	}, nil
}

func (c *GiteaClientImpl) getCommitCount(ctx context.Context, owner, repo string) int {
	urlStr := fmt.Sprintf("%s/repos/%s/%s/commits?limit=1", c.baseURL, url.PathEscape(owner), url.PathEscape(repo))
	return c.getCountFromHeader(ctx, urlStr)
}

func (c *GiteaClientImpl) getBranchCount(ctx context.Context, owner, repo string) int {
	urlStr := fmt.Sprintf("%s/repos/%s/%s/branches?limit=1", c.baseURL, url.PathEscape(owner), url.PathEscape(repo))
	return c.getCountFromHeader(ctx, urlStr)
}

func (c *GiteaClientImpl) getReleaseCount(ctx context.Context, owner, repo string) int {
	urlStr := fmt.Sprintf("%s/repos/%s/%s/releases?limit=1", c.baseURL, url.PathEscape(owner), url.PathEscape(repo))
	return c.getCountFromHeader(ctx, urlStr)
}

func (c *GiteaClientImpl) getCountFromHeader(ctx context.Context, urlStr string) int {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, urlStr, nil)
	if err != nil {
		return 0
	}

	if c.token != "" {
		req.Header.Set("Authorization", "token "+c.token)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return 0
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0
	}

	// Gitea returns X-Total-Count header
	if total := resp.Header.Get("X-Total-Count"); total != "" {
		if count, err := strconv.Atoi(total); err == nil {
			return count
		}
	}

	// Fallback: count items
	body, _ := io.ReadAll(resp.Body)
	var items []interface{}
	if json.Unmarshal(body, &items) == nil {
		return len(items)
	}

	return 0
}

// GetReadme fetches the README content for a repository.
func (c *GiteaClientImpl) GetReadme(ctx context.Context, owner, repo string) (string, error) {
	urlStr := fmt.Sprintf("%s/repos/%s/%s/raw/README.md", c.baseURL, url.PathEscape(owner), url.PathEscape(repo))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, urlStr, nil)
	if err != nil {
		return "", err
	}

	if c.token != "" {
		req.Header.Set("Authorization", "token "+c.token)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		// Try without .md extension
		urlStr = fmt.Sprintf("%s/repos/%s/%s/raw/README", c.baseURL, url.PathEscape(owner), url.PathEscape(repo))
		req, _ = http.NewRequestWithContext(ctx, http.MethodGet, urlStr, nil)
		if c.token != "" {
			req.Header.Set("Authorization", "token "+c.token)
		}
		resp, err = c.httpClient.Do(req)
		if err != nil {
			return "", nil
		}
		defer resp.Body.Close()
	}

	if resp.StatusCode != http.StatusOK {
		return "", nil
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return string(body), nil
}
