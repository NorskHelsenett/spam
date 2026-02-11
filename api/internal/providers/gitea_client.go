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
			Languages:     toLanguagesArray(r.Language),
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
			Languages:     toLanguagesArray(r.Language),
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

// GetLatestCommit returns the SHA of the latest commit on the given ref (branch).
func (c *GiteaClientImpl) GetLatestCommit(ctx context.Context, repoPath string, ref string) (string, error) {
	parts := strings.SplitN(repoPath, "/", 2)
	if len(parts) != 2 {
		return "", fmt.Errorf("invalid repo path: %s", repoPath)
	}
	owner, repo := parts[0], parts[1]

	urlStr := fmt.Sprintf("%s/repos/%s/%s/git/commits?sha=%s&limit=1",
		c.baseURL, url.PathEscape(owner), url.PathEscape(repo), url.QueryEscape(ref))

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
			Languages:     toLanguagesArray(gRepo.Language),
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

// GetCommitLog fetches recent commits for a repository.
func (c *GiteaClientImpl) GetCommitLog(ctx context.Context, owner, repo string, limit int) ([]CommitInfo, error) {
	if limit <= 0 {
		limit = 20
	}
	urlStr := fmt.Sprintf("%s/repos/%s/%s/git/commits?limit=%d",
		c.baseURL, url.PathEscape(owner), url.PathEscape(repo), limit)

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

	var giteaCommits []struct {
		SHA     string `json:"sha"`
		HTMLURL string `json:"html_url"`
		Commit  struct {
			Message string `json:"message"`
			Author  struct {
				Name  string    `json:"name"`
				Email string    `json:"email"`
				Date  time.Time `json:"date"`
			} `json:"author"`
		} `json:"commit"`
		Author *struct {
			Login     string `json:"login"`
			AvatarURL string `json:"avatar_url"`
		} `json:"author"`
	}
	if err := json.Unmarshal(body, &giteaCommits); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidResponse, err)
	}

	commits := make([]CommitInfo, len(giteaCommits))
	for i, c := range giteaCommits {
		message := c.Commit.Message
		if idx := strings.IndexByte(message, '\n'); idx > 0 {
			message = message[:idx]
		}

		ci := CommitInfo{
			SHA:         c.SHA,
			Message:     message,
			AuthorName:  c.Commit.Author.Name,
			AuthorEmail: c.Commit.Author.Email,
			AuthorDate:  c.Commit.Author.Date,
			CommitURL:   c.HTMLURL,
		}
		if c.Author != nil {
			ci.AuthorLogin = c.Author.Login
			ci.AuthorAvatar = c.Author.AvatarURL
		}
		commits[i] = ci
	}

	return commits, nil
}

// GetContributors fetches contributors for a repository.
// Falls back to extracting unique authors from recent commits if the contributors endpoint is unavailable.
func (c *GiteaClientImpl) GetContributors(ctx context.Context, owner, repo string, limit int) ([]ContributorInfo, error) {
	if limit <= 0 {
		limit = 30
	}

	// Try the activity/contributors endpoint (available in newer Gitea/Forgejo)
	urlStr := fmt.Sprintf("%s/repos/%s/%s/contributors",
		c.baseURL, url.PathEscape(owner), url.PathEscape(repo))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, urlStr, nil)
	if err != nil {
		return nil, err
	}

	if c.token != "" {
		req.Header.Set("Authorization", "token "+c.token)
	}

	resp, err := c.httpClient.Do(req)
	if err == nil {
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			body, err := io.ReadAll(resp.Body)
			if err == nil {
				var giteaContribs []struct {
					Login         string `json:"login"`
					AvatarURL     string `json:"avatar_url"`
					HTMLURL       string `json:"html_url"`
					Contributions int    `json:"contributions"`
					Name          string `json:"name"`
					Email         string `json:"email"`
				}
				if json.Unmarshal(body, &giteaContribs) == nil && len(giteaContribs) > 0 {
					result := make([]ContributorInfo, 0, len(giteaContribs))
					for _, c := range giteaContribs {
						if len(result) >= limit {
							break
						}
						result = append(result, ContributorInfo{
							Login:         c.Login,
							Name:          c.Name,
							Email:         c.Email,
							AvatarURL:     c.AvatarURL,
							ProfileURL:    c.HTMLURL,
							Contributions: c.Contributions,
						})
					}
					return result, nil
				}
			}
		}
	}

	// Fallback: extract unique authors from recent commits
	return c.contributorsFromCommits(ctx, owner, repo, limit)
}

// contributorsFromCommits builds a contributors list from recent commit authors.
func (c *GiteaClientImpl) contributorsFromCommits(ctx context.Context, owner, repo string, limit int) ([]ContributorInfo, error) {
	commits, err := c.GetCommitLog(ctx, owner, repo, 100)
	if err != nil {
		return nil, err
	}

	type authorKey struct{ name, email string }
	counts := make(map[authorKey]*ContributorInfo)
	var order []authorKey

	for _, cm := range commits {
		key := authorKey{cm.AuthorName, cm.AuthorEmail}
		if existing, ok := counts[key]; ok {
			existing.Contributions++
		} else {
			counts[key] = &ContributorInfo{
				Login:         cm.AuthorLogin,
				Name:          cm.AuthorName,
				Email:         cm.AuthorEmail,
				AvatarURL:     cm.AuthorAvatar,
				Contributions: 1,
			}
			order = append(order, key)
		}
	}

	result := make([]ContributorInfo, 0, len(order))
	for _, key := range order {
		result = append(result, *counts[key])
	}

	// Sort by contributions descending
	for i := 0; i < len(result)-1; i++ {
		for j := i + 1; j < len(result); j++ {
			if result[j].Contributions > result[i].Contributions {
				result[i], result[j] = result[j], result[i]
			}
		}
	}

	if len(result) > limit {
		result = result[:limit]
	}

	return result, nil
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
