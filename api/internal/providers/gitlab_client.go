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
	"sync"
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
	// Ensure /api/v4 suffix
	if !strings.HasSuffix(baseURL, "/api/v4") {
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
	Language          string    `json:"language"`
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

// ListPublicProjects lists projects for a group or instance.
// If authenticated, private projects may be included.
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

	visibility := "visibility=public&"
	if c.token != "" {
		visibility = ""
	}

	var urlStr string
	if groupPath != "" {
		// URL-encode the group path (GitLab uses / in group paths)
		encodedPath := url.PathEscape(groupPath)
		urlStr = fmt.Sprintf("%s/groups/%s/projects?%sper_page=%d&page=%d&include_subgroups=%v&order_by=last_activity_at&sort=desc",
			c.baseURL, encodedPath, visibility, opts.PageSize, opts.Page, opts.IncludeSubgroups)
	} else {
		// List all projects on the instance
		urlStr = fmt.Sprintf("%s/projects?%sper_page=%d&page=%d&order_by=last_activity_at&sort=desc",
			c.baseURL, visibility, opts.PageSize, opts.Page)
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
			Languages:     nil, // Will be populated by fetchLanguagesParallel
			IsPrivate:     p.Visibility != "public",
			IsArchived:    p.Archived,
			IsFork:        p.ForkedFromProject != nil,
			Topics:        p.Topics,
			CreatedAt:     p.CreatedAt,
			UpdatedAt:     p.LastActivityAt,
			PushedAt:      p.LastActivityAt, // GitLab doesn't separate pushed_at
		}
	}

	// Fetch languages in parallel for all projects
	c.fetchLanguagesParallel(ctx, repos)

	pageInfo := c.parsePageInfo(resp)
	return repos, pageInfo, nil
}

// ListPublicGroups lists groups, including private groups when authenticated.
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
		// List top-level groups
		visibility := "visibility=public&"
		if c.token != "" {
			visibility = ""
		}
		urlStr = fmt.Sprintf("%s/groups?%sper_page=%d&page=%d&top_level_only=true&order_by=name",
			c.baseURL, visibility, opts.PageSize, opts.Page)
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

// GetLatestCommit returns the SHA of the latest commit on the given ref (branch).
func (c *GitLabClientImpl) GetLatestCommit(ctx context.Context, repoPath string, ref string) (string, error) {
	encodedPath := url.PathEscape(repoPath)
	urlStr := fmt.Sprintf("%s/projects/%s/repository/commits?ref_name=%s&per_page=1", c.baseURL, encodedPath, url.QueryEscape(ref))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, urlStr, nil)
	if err != nil {
		return "", err
	}

	if c.token != "" {
		req.Header.Set("PRIVATE-TOKEN", c.token)
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
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &commits); err != nil {
		return "", fmt.Errorf("%w: %v", ErrInvalidResponse, err)
	}
	if len(commits) == 0 {
		return "", ErrNotFound
	}

	return commits[0].ID, nil
}

// gitLabProjectDetails represents detailed project info from GitLab API.
type gitLabProjectDetails struct {
	gitLabProject
	StarCount       int `json:"star_count"`
	ForksCount      int `json:"forks_count"`
	OpenIssuesCount int `json:"open_issues_count"`
	Statistics      *struct {
		CommitCount int `json:"commit_count"`
	} `json:"statistics"`
	License *struct {
		Name string `json:"name"`
	} `json:"license"`
}

// GetRepoDetails fetches detailed information about a project.
func (c *GitLabClientImpl) GetRepoDetails(ctx context.Context, projectPath string) (*RepoDetails, error) {
	encodedPath := url.PathEscape(projectPath)
	urlStr := fmt.Sprintf("%s/projects/%s?statistics=true&license=true", c.baseURL, encodedPath)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, urlStr, nil)
	if err != nil {
		return nil, err
	}

	if c.token != "" {
		req.Header.Set("PRIVATE-TOKEN", c.token)
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

	var glProject gitLabProjectDetails
	if err := json.Unmarshal(body, &glProject); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidResponse, err)
	}

	commitCount := 0
	if glProject.Statistics != nil {
		commitCount = glProject.Statistics.CommitCount
	}

	stats := RepoStats{
		Stars:      glProject.StarCount,
		Forks:      glProject.ForksCount,
		OpenIssues: glProject.OpenIssuesCount,
		Commits:    commitCount,
	}

	// Fetch additional counts
	stats.Branches = c.getBranchCount(ctx, projectPath)
	stats.Releases = c.getReleaseCount(ctx, projectPath)
	stats.Contributors = c.getContributorCount(ctx, projectPath)

	// If statistics didn't include commit count, fetch via commits API
	if stats.Commits == 0 {
		stats.Commits = c.getCommitCount(ctx, projectPath)
	}

	license := ""
	if glProject.License != nil {
		license = glProject.License.Name
	}

	// Fetch languages from languages endpoint (GitLab doesn't include it in project response)
	languages := c.getLanguages(ctx, projectPath)

	return &RepoDetails{
		RepoData: RepoData{
			ExternalID:    strconv.FormatInt(glProject.ID, 10),
			Name:          glProject.Name,
			FullPath:      glProject.PathWithNamespace,
			Description:   glProject.Description,
			HTMLURL:       glProject.WebURL,
			DefaultBranch: glProject.DefaultBranch,
			Languages:     languages,
			IsPrivate:     glProject.Visibility != "public",
			IsArchived:    glProject.Archived,
			IsFork:        glProject.ForkedFromProject != nil,
			Topics:        glProject.Topics,
			CreatedAt:     glProject.CreatedAt,
			UpdatedAt:     glProject.LastActivityAt,
			PushedAt:      glProject.LastActivityAt,
		},
		Stats:   stats,
		License: license,
	}, nil
}

func (c *GitLabClientImpl) getCommitCount(ctx context.Context, projectPath string) int {
	encodedPath := url.PathEscape(projectPath)
	urlStr := fmt.Sprintf("%s/projects/%s/repository/commits?per_page=1", c.baseURL, encodedPath)
	return c.getCountFromHeader(ctx, urlStr)
}

func (c *GitLabClientImpl) getBranchCount(ctx context.Context, projectPath string) int {
	encodedPath := url.PathEscape(projectPath)
	urlStr := fmt.Sprintf("%s/projects/%s/repository/branches?per_page=1", c.baseURL, encodedPath)
	return c.getCountFromHeader(ctx, urlStr)
}

func (c *GitLabClientImpl) getReleaseCount(ctx context.Context, projectPath string) int {
	encodedPath := url.PathEscape(projectPath)
	urlStr := fmt.Sprintf("%s/projects/%s/releases?per_page=1", c.baseURL, encodedPath)
	return c.getCountFromHeader(ctx, urlStr)
}

func (c *GitLabClientImpl) getContributorCount(ctx context.Context, projectPath string) int {
	encodedPath := url.PathEscape(projectPath)
	urlStr := fmt.Sprintf("%s/projects/%s/repository/contributors?per_page=1", c.baseURL, encodedPath)
	return c.getCountFromHeader(ctx, urlStr)
}

// fetchLanguagesParallel fetches languages for all repos in parallel.
func (c *GitLabClientImpl) fetchLanguagesParallel(ctx context.Context, repos []RepoData) {
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

// getLanguages fetches all languages for a project, sorted by percentage descending.
func (c *GitLabClientImpl) getLanguages(ctx context.Context, projectPath string) []string {
	encodedPath := url.PathEscape(projectPath)
	urlStr := fmt.Sprintf("%s/projects/%s/languages", c.baseURL, encodedPath)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, urlStr, nil)
	if err != nil {
		return nil
	}

	if c.token != "" {
		req.Header.Set("PRIVATE-TOKEN", c.token)
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

	// Response is map of language -> percentage, e.g. {"Go": 100.0, "Shell": 0.5}
	var languageMap map[string]float64
	if err := json.Unmarshal(body, &languageMap); err != nil {
		return nil
	}

	if len(languageMap) == 0 {
		return nil
	}

	// Sort languages by percentage descending
	type langPct struct {
		lang string
		pct  float64
	}
	sorted := make([]langPct, 0, len(languageMap))
	for lang, pct := range languageMap {
		sorted = append(sorted, langPct{lang, pct})
	}
	for i := 0; i < len(sorted)-1; i++ {
		for j := i + 1; j < len(sorted); j++ {
			if sorted[j].pct > sorted[i].pct {
				sorted[i], sorted[j] = sorted[j], sorted[i]
			}
		}
	}

	result := make([]string, len(sorted))
	for i, lp := range sorted {
		result[i] = lp.lang
	}
	return result
}

func (c *GitLabClientImpl) getCountFromHeader(ctx context.Context, urlStr string) int {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, urlStr, nil)
	if err != nil {
		return 0
	}

	if c.token != "" {
		req.Header.Set("PRIVATE-TOKEN", c.token)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return 0
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0
	}

	// GitLab returns X-Total header for total item count
	if total := resp.Header.Get("X-Total"); total != "" {
		if count, err := strconv.Atoi(total); err == nil {
			return count
		}
	}

	// Fallback: X-Total-Pages equals total count when per_page=1
	if totalPages := resp.Header.Get("X-Total-Pages"); totalPages != "" {
		if count, err := strconv.Atoi(totalPages); err == nil {
			return count
		}
	}

	// Last fallback: count items in response
	body, _ := io.ReadAll(resp.Body)
	var items []interface{}
	if json.Unmarshal(body, &items) == nil {
		return len(items)
	}

	return 0
}

// GetCommitLog fetches recent commits for a project.
func (c *GitLabClientImpl) GetCommitLog(ctx context.Context, projectPath string, limit int) ([]CommitInfo, error) {
	if limit <= 0 {
		limit = 20
	}
	encodedPath := url.PathEscape(projectPath)
	urlStr := fmt.Sprintf("%s/projects/%s/repository/commits?per_page=%d", c.baseURL, encodedPath, limit)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, urlStr, nil)
	if err != nil {
		return nil, err
	}

	if c.token != "" {
		req.Header.Set("PRIVATE-TOKEN", c.token)
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

	var glCommits []struct {
		ID             string    `json:"id"`
		Title          string    `json:"title"`
		AuthorName     string    `json:"author_name"`
		AuthorEmail    string    `json:"author_email"`
		AuthoredDate   time.Time `json:"authored_date"`
		WebURL         string    `json:"web_url"`
	}
	if err := json.Unmarshal(body, &glCommits); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidResponse, err)
	}

	commits := make([]CommitInfo, len(glCommits))
	for i, c := range glCommits {
		commits[i] = CommitInfo{
			SHA:         c.ID,
			Message:     c.Title,
			AuthorName:  c.AuthorName,
			AuthorEmail: c.AuthorEmail,
			AuthorDate:  c.AuthoredDate,
			CommitURL:   c.WebURL,
		}
	}

	return commits, nil
}

// GetContributors fetches contributors for a project.
func (c *GitLabClientImpl) GetContributors(ctx context.Context, projectPath string, limit int) ([]ContributorInfo, error) {
	if limit <= 0 {
		limit = 30
	}
	encodedPath := url.PathEscape(projectPath)
	urlStr := fmt.Sprintf("%s/projects/%s/repository/contributors?per_page=%d&order_by=commits&sort=desc", c.baseURL, encodedPath, limit)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, urlStr, nil)
	if err != nil {
		return nil, err
	}

	if c.token != "" {
		req.Header.Set("PRIVATE-TOKEN", c.token)
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

	var glContributors []struct {
		Name    string `json:"name"`
		Email   string `json:"email"`
		Commits int    `json:"commits"`
	}
	if err := json.Unmarshal(body, &glContributors); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidResponse, err)
	}

	contributors := make([]ContributorInfo, len(glContributors))
	for i, c := range glContributors {
		contributors[i] = ContributorInfo{
			Name:          c.Name,
			Email:         c.Email,
			Contributions: c.Commits,
		}
	}

	return contributors, nil
}

// GetReadme fetches the README content for a project.
func (c *GitLabClientImpl) GetReadme(ctx context.Context, projectPath string) (string, error) {
	encodedPath := url.PathEscape(projectPath)

	// First, try the dedicated README endpoint (available in newer GitLab versions)
	urlStr := fmt.Sprintf("%s/projects/%s/repository/files/README.md/raw?ref=HEAD", c.baseURL, encodedPath)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, urlStr, nil)
	if err != nil {
		return "", nil
	}

	if c.token != "" {
		req.Header.Set("PRIVATE-TOKEN", c.token)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", nil
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return "", nil
		}
		return string(body), nil
	}

	// If that fails, try fetching via the blob endpoint (works without auth for public projects)
	// First get the default branch from project info we should already have
	// Try lowercase readme.md
	urlStr = fmt.Sprintf("%s/projects/%s/repository/files/readme.md/raw?ref=HEAD", c.baseURL, encodedPath)
	req, err = http.NewRequestWithContext(ctx, http.MethodGet, urlStr, nil)
	if err != nil {
		return "", nil
	}

	if c.token != "" {
		req.Header.Set("PRIVATE-TOKEN", c.token)
	}

	resp, err = c.httpClient.Do(req)
	if err != nil {
		return "", nil
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return "", nil
		}
		return string(body), nil
	}

	return "", nil // No README found or requires authentication
}
