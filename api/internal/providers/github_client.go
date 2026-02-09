package providers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
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
	Disabled      bool      `json:"disabled"`
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

// toLanguagesArray converts a single language string to a slice.
func toLanguagesArray(lang string) []string {
	if lang == "" {
		return nil
	}
	return []string{lang}
}

// fetchLanguagesParallel fetches languages for all repos in parallel.
func (c *GitHubClientImpl) fetchLanguagesParallel(ctx context.Context, repos []RepoData) {
	if len(repos) == 0 {
		return
	}

	var wg sync.WaitGroup
	for i := range repos {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			repos[idx].Languages = c.getLanguages(ctx, repos[idx].FullPath)
		}(i)
	}
	wg.Wait()
}

// getLanguages fetches all languages for a repo, sorted by bytes descending.
func (c *GitHubClientImpl) getLanguages(ctx context.Context, fullPath string) []string {
	url := fmt.Sprintf("%s/repos/%s/languages", c.baseURL, fullPath)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil
	}

	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil
	}

	// Response is map of language -> bytes, e.g. {"Go": 974056, "Shell": 15280}
	var languageMap map[string]int64
	if err := json.Unmarshal(body, &languageMap); err != nil {
		return nil
	}

	if len(languageMap) == 0 {
		return nil
	}

	// Sort languages by bytes descending
	type langBytes struct {
		lang  string
		bytes int64
	}
	sorted := make([]langBytes, 0, len(languageMap))
	for lang, bytes := range languageMap {
		sorted = append(sorted, langBytes{lang, bytes})
	}
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].bytes > sorted[j].bytes
	})

	result := make([]string, len(sorted))
	for i, lb := range sorted {
		result[i] = lb.lang
	}
	return result
}

// ListPublicRepos lists repositories for a user or organization.
// If authenticated, private repositories may be included.
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
	repoType := "public"
	if c.token != "" {
		repoType = "all"
	}
	url := fmt.Sprintf("%s/orgs/%s/repos?type=%s&per_page=%d&page=%d",
		c.baseURL, org, repoType, opts.PageSize, opts.Page)
	return c.fetchRepos(ctx, url, opts.PageSize)
}

func (c *GitHubClientImpl) listUserRepos(ctx context.Context, username string, opts ListOptions) ([]RepoData, PageInfo, error) {
	repoType := "public"
	if c.token != "" {
		repoType = "all"
	}
	url := fmt.Sprintf("%s/users/%s/repos?type=%s&per_page=%d&page=%d",
		c.baseURL, username, repoType, opts.PageSize, opts.Page)
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
			Languages:     nil, // Will be populated by fetchLanguagesParallel
			IsPrivate:     r.Private,
			IsArchived:    r.Archived,
			IsDisabled:    r.Disabled,
			IsFork:        r.Fork,
			Topics:        r.Topics,
			CreatedAt:     r.CreatedAt,
			UpdatedAt:     r.UpdatedAt,
			PushedAt:      r.PushedAt,
		}
	}

	// Fetch languages in parallel for all repos
	c.fetchLanguagesParallel(ctx, repos)

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
	// Look for &page= or ?page= to avoid matching per_page=
	idx := strings.Index(urlStr, "&page=")
	if idx < 0 {
		idx = strings.Index(urlStr, "?page=")
	}
	if idx < 0 {
		return 0
	}
	// Skip the &page= or ?page= prefix (6 chars)
	pageStr := urlStr[idx+6:]
	if endIdx := strings.IndexAny(pageStr, "&>"); endIdx > 0 {
		pageStr = pageStr[:endIdx]
	}
	page, err := strconv.Atoi(pageStr)
	if err != nil {
		return 0
	}
	return page
}

// GetLatestCommit returns the SHA of the latest commit on the given ref (branch).
func (c *GitHubClientImpl) GetLatestCommit(ctx context.Context, repoPath string, ref string) (string, error) {
	url := fmt.Sprintf("%s/repos/%s/commits?sha=%s&per_page=1", c.baseURL, repoPath, ref)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}

	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if err := c.checkResponse(resp); err != nil {
		return "", err
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	var commits []struct {
		SHA string `json:"sha"`
	}
	if err := json.Unmarshal(body, &commits); err != nil {
		return "", fmt.Errorf("%w: %v", ErrInvalidResponse, err)
	}
	if len(commits) == 0 {
		return "", ErrNotFound
	}

	return commits[0].SHA, nil
}

// gitHubRepoDetails represents detailed repo info from GitHub API.
type gitHubRepoDetails struct {
	gitHubRepo
	StargazersCount int   `json:"stargazers_count"`
	ForksCount      int   `json:"forks_count"`
	WatchersCount   int   `json:"watchers_count"`
	OpenIssuesCount int   `json:"open_issues_count"`
	Size            int64 `json:"size"`
	License         *struct {
		Name string `json:"name"`
	} `json:"license"`
}

// GetRepoDetails fetches detailed information about a repository.
func (c *GitHubClientImpl) GetRepoDetails(ctx context.Context, owner, repo string) (*RepoDetails, error) {
	url := fmt.Sprintf("%s/repos/%s/%s", c.baseURL, owner, repo)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
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

	var ghRepo gitHubRepoDetails
	if err := json.Unmarshal(body, &ghRepo); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidResponse, err)
	}

	// Fetch additional stats
	stats := RepoStats{
		Stars:      ghRepo.StargazersCount,
		Forks:      ghRepo.ForksCount,
		Watchers:   ghRepo.WatchersCount,
		OpenIssues: ghRepo.OpenIssuesCount,
	}

	// Fetch counts in parallel
	stats.Commits = c.getCommitCount(ctx, owner, repo)
	stats.Branches = c.getBranchCount(ctx, owner, repo)
	stats.Releases = c.getReleaseCount(ctx, owner, repo)
	stats.Contributors = c.getContributorCount(ctx, owner, repo)

	license := ""
	if ghRepo.License != nil {
		license = ghRepo.License.Name
	}

	// Fetch all languages
	languages := c.getLanguages(ctx, ghRepo.FullName)

	return &RepoDetails{
		RepoData: RepoData{
			ExternalID:    strconv.FormatInt(ghRepo.ID, 10),
			Name:          ghRepo.Name,
			FullPath:      ghRepo.FullName,
			Description:   ghRepo.Description,
			HTMLURL:       ghRepo.HTMLURL,
			DefaultBranch: ghRepo.DefaultBranch,
			Languages:     languages,
			IsPrivate:     ghRepo.Private,
			IsArchived:    ghRepo.Archived,
			IsDisabled:    ghRepo.Disabled,
			IsFork:        ghRepo.Fork,
			Topics:        ghRepo.Topics,
			CreatedAt:     ghRepo.CreatedAt,
			UpdatedAt:     ghRepo.UpdatedAt,
			PushedAt:      ghRepo.PushedAt,
		},
		Stats:   stats,
		License: license,
		Size:    ghRepo.Size,
	}, nil
}

func (c *GitHubClientImpl) getCommitCount(ctx context.Context, owner, repo string) int {
	url := fmt.Sprintf("%s/repos/%s/%s/commits?per_page=1", c.baseURL, owner, repo)
	return c.getCountFromLinkHeader(ctx, url)
}

func (c *GitHubClientImpl) getBranchCount(ctx context.Context, owner, repo string) int {
	url := fmt.Sprintf("%s/repos/%s/%s/branches?per_page=1", c.baseURL, owner, repo)
	return c.getCountFromLinkHeader(ctx, url)
}

func (c *GitHubClientImpl) getReleaseCount(ctx context.Context, owner, repo string) int {
	url := fmt.Sprintf("%s/repos/%s/%s/releases?per_page=1", c.baseURL, owner, repo)
	return c.getCountFromLinkHeader(ctx, url)
}

func (c *GitHubClientImpl) getContributorCount(ctx context.Context, owner, repo string) int {
	url := fmt.Sprintf("%s/repos/%s/%s/contributors?per_page=1&anon=true", c.baseURL, owner, repo)
	return c.getCountFromLinkHeader(ctx, url)
}

func (c *GitHubClientImpl) getCountFromLinkHeader(ctx context.Context, url string) int {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0
	}

	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return 0
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0
	}

	// Parse Link header to get last page
	linkHeader := resp.Header.Get("Link")
	if linkHeader == "" {
		// No pagination means single page, count the items
		body, _ := io.ReadAll(resp.Body)
		var items []interface{}
		if json.Unmarshal(body, &items) == nil {
			return len(items)
		}
		return 1
	}

	// Extract last page number
	for _, link := range strings.Split(linkHeader, ",") {
		if strings.Contains(link, `rel="last"`) {
			return extractPageParam(link)
		}
	}

	return 1
}

// GetReadme fetches the README content for a repository.
func (c *GitHubClientImpl) GetReadme(ctx context.Context, owner, repo string) (string, error) {
	url := fmt.Sprintf("%s/repos/%s/%s/readme", c.baseURL, owner, repo)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}

	// Request raw content - use application/vnd.github.raw for raw file content
	req.Header.Set("Accept", "application/vnd.github.raw")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return "", nil // No README
	}

	if resp.StatusCode != http.StatusOK {
		return "", nil // Other error, skip README
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return string(body), nil
}
