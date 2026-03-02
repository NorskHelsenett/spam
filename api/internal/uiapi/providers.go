package uiapi

import (
	"context"
	"crypto/md5"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/NorskHelsenett/spam/internal/auth"
	"github.com/NorskHelsenett/spam/internal/cache"
	"github.com/NorskHelsenett/spam/internal/providerconfig"
	"github.com/NorskHelsenett/spam/internal/providers"
)

// GitHubReposResponse is the response for the GitHub repos endpoint.
type GitHubReposResponse struct {
	Repos       []providers.RepoData `json:"repos"`
	TotalCount  int                  `json:"total_count"`
	Page        int                  `json:"page"`
	PageSize    int                  `json:"page_size"`
	HasNextPage bool                 `json:"has_next_page"`
	NextPage    int                  `json:"next_page"`
}

// GitLabProjectsResponse is the response for the GitLab projects endpoint.
type GitLabProjectsResponse struct {
	Projects    []providers.RepoData `json:"projects"`
	TotalCount  int                  `json:"total_count"`
	Page        int                  `json:"page"`
	PageSize    int                  `json:"page_size"`
	HasNextPage bool                 `json:"has_next_page"`
	NextPage    int                  `json:"next_page"`
}

// GitLabGroupsResponse is the response for the GitLab groups endpoint.
type GitLabGroupsResponse struct {
	Groups      []providers.GroupData `json:"groups"`
	TotalCount  int                   `json:"total_count"`
	Page        int                   `json:"page"`
	PageSize    int                   `json:"page_size"`
	HasNextPage bool                  `json:"has_next_page"`
	NextPage    int                   `json:"next_page"`
}

func resolveProviderToken(r *http.Request, store *providerconfig.Store) (string, error) {
	if store == nil {
		return "", nil
	}
	providerID := strings.TrimSpace(r.URL.Query().Get("provider_id"))
	if providerID == "" {
		return "", nil
	}
	return store.GetActiveToken(r.Context(), providerID)
}

// resolveProviderTokenByBaseURL resolves the provider token using provider_id if present,
// otherwise falls back to looking up the provider by base_url and repoPath.
func resolveProviderTokenByBaseURL(r *http.Request, store *providerconfig.Store, providerType, repoPath string) (string, error) {
	token, err := resolveProviderToken(r, store)
	if err != nil || token != "" {
		return token, err
	}
	baseURL := r.URL.Query().Get("base_url")
	if baseURL == "" || store == nil {
		return "", nil
	}
	return store.GetActiveTokenByBaseURL(r.Context(), providerType, baseURL, repoPath)
}

// GitHubReposHandler handles the GitHub repos endpoint.
// GET /api/providers/github/{owner}/repos
// defaultListCacheTTL is used when no provider_id is present or poll_interval is unset.
const defaultListCacheTTL = 10 * time.Minute

// resolvePollTTL returns the provider's configured poll_interval as a cache TTL,
// falling back to defaultListCacheTTL if the provider_id param is absent or unset.
func resolvePollTTL(r *http.Request, store *providerconfig.Store) time.Duration {
	providerID := r.URL.Query().Get("provider_id")
	return store.GetPollInterval(r.Context(), providerID, defaultListCacheTTL)
}

func GitHubReposHandler(authService *auth.Service, store *providerconfig.Store, c cache.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if requireAuth(w, r, authService) == nil {
			return
		}

		owner := r.PathValue("owner")
		if owner == "" {
			http.Error(w, "owner is required", http.StatusBadRequest)
			return
		}

		page, pageSize := parsePagination(r)
		sortColumn := r.URL.Query().Get("sort")
		sortOrder := r.URL.Query().Get("order")

		cacheKey := fmt.Sprintf("github:repos:%s:p%d:ps%d:s%s:o%s", owner, page, pageSize, sortColumn, sortOrder)
		if cached, ok, _ := cache.GetJSON[GitHubReposResponse](r.Context(), c, cacheKey); ok {
			writeJSON(w, http.StatusOK, cached)
			return
		}

		token, err := resolveProviderToken(r, store)
		if err != nil {
			http.Error(w, "failed to load provider token", http.StatusInternalServerError)
			return
		}

		client := providers.NewGitHubClient("", token)
		repos, pageInfo, err := client.ListPublicRepos(r.Context(), owner, providers.ListOptions{
			Page:     page,
			PageSize: pageSize,
		})
		if err != nil {
			log.Printf("GitHub API error for owner %q: %v", owner, err)
			if errors.Is(err, providers.ErrNotFound) {
				http.Error(w, "owner not found", http.StatusNotFound)
				return
			}
			if errors.Is(err, providers.ErrUnauthorized) {
				http.Error(w, "authentication required for this GitHub org/user", http.StatusUnauthorized)
				return
			}
			if errors.Is(err, providers.ErrRateLimited) {
				http.Error(w, "Rate limited by GitHub API. Try again later.", http.StatusTooManyRequests)
				return
			}
			http.Error(w, "failed to fetch repos", http.StatusInternalServerError)
			return
		}

		if sortColumn != "" {
			sortRepos(repos, sortColumn, sortOrder)
		}

		resp := GitHubReposResponse{
			Repos:       repos,
			TotalCount:  pageInfo.TotalCount,
			Page:        page,
			PageSize:    pageSize,
			HasNextPage: pageInfo.HasNextPage,
			NextPage:    pageInfo.NextPage,
		}
		_ = cache.SetJSON(r.Context(), c, cacheKey, resp, resolvePollTTL(r, store))
		writeJSON(w, http.StatusOK, resp)
	}
}

// GitLabProjectsHandler handles the GitLab projects endpoint.
// GET /api/providers/gitlab/{group}/projects?base_url=https://gitlab.example.com
func GitLabProjectsHandler(authService *auth.Service, store *providerconfig.Store, c cache.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if requireAuth(w, r, authService) == nil {
			return
		}

		group := r.PathValue("group")
		// group can be empty to list all public projects

		page, pageSize := parsePagination(r)
		includeSubgroups := r.URL.Query().Get("include_subgroups") == "true"
		baseURL := r.URL.Query().Get("base_url") // Custom instance URL
		sortColumn := r.URL.Query().Get("sort")
		sortOrder := r.URL.Query().Get("order")

		cacheKey := fmt.Sprintf("gitlab:projects:%s:%s:p%d:ps%d:sub%v:s%s:o%s", baseURL, group, page, pageSize, includeSubgroups, sortColumn, sortOrder)
		if cached, ok, _ := cache.GetJSON[GitLabProjectsResponse](r.Context(), c, cacheKey); ok {
			writeJSON(w, http.StatusOK, cached)
			return
		}

		token, err := resolveProviderToken(r, store)
		if err != nil {
			http.Error(w, "failed to load provider token", http.StatusInternalServerError)
			return
		}

		client := providers.NewGitLabClient(baseURL, token)
		projects, pageInfo, err := client.ListPublicProjects(r.Context(), group, providers.ListOptions{
			Page:             page,
			PageSize:         pageSize,
			IncludeSubgroups: includeSubgroups,
		})
		if err != nil {
			log.Printf("GitLab API error for group %q: %v", group, err)
			if errors.Is(err, providers.ErrNotFound) {
				http.Error(w, "group not found", http.StatusNotFound)
				return
			}
			if errors.Is(err, providers.ErrUnauthorized) {
				http.Error(w, "authentication required for this GitLab instance", http.StatusUnauthorized)
				return
			}
			if errors.Is(err, providers.ErrRateLimited) {
				http.Error(w, "rate limited", http.StatusTooManyRequests)
				return
			}
			http.Error(w, "failed to fetch projects", http.StatusInternalServerError)
			return
		}

		if sortColumn != "" {
			sortRepos(projects, sortColumn, sortOrder)
		}

		resp := GitLabProjectsResponse{
			Projects:    projects,
			TotalCount:  pageInfo.TotalCount,
			Page:        page,
			PageSize:    pageSize,
			HasNextPage: pageInfo.HasNextPage,
			NextPage:    pageInfo.NextPage,
		}
		_ = cache.SetJSON(r.Context(), c, cacheKey, resp, resolvePollTTL(r, store))
		writeJSON(w, http.StatusOK, resp)
	}
}

// GitLabSubgroupsHandler handles the GitLab subgroups endpoint.
// GET /api/providers/gitlab/{group}/subgroups?base_url=https://gitlab.example.com
func GitLabSubgroupsHandler(authService *auth.Service, store *providerconfig.Store, c cache.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if requireAuth(w, r, authService) == nil {
			return
		}

		group := r.PathValue("group")
		page, pageSize := parsePagination(r)
		baseURL := r.URL.Query().Get("base_url")

		cacheKey := fmt.Sprintf("gitlab:subgroups:%s:%s:p%d:ps%d", baseURL, group, page, pageSize)
		if cached, ok, _ := cache.GetJSON[GitLabGroupsResponse](r.Context(), c, cacheKey); ok {
			writeJSON(w, http.StatusOK, cached)
			return
		}

		token, err := resolveProviderToken(r, store)
		if err != nil {
			http.Error(w, "failed to load provider token", http.StatusInternalServerError)
			return
		}

		client := providers.NewGitLabClient(baseURL, token)
		groups, pageInfo, err := client.ListPublicGroups(r.Context(), group, providers.ListOptions{
			Page:     page,
			PageSize: pageSize,
		})
		if err != nil {
			log.Printf("GitLab API error for group %q subgroups: %v", group, err)
			if errors.Is(err, providers.ErrNotFound) {
				http.Error(w, "group not found", http.StatusNotFound)
				return
			}
			if errors.Is(err, providers.ErrUnauthorized) {
				http.Error(w, "authentication required for this GitLab instance", http.StatusUnauthorized)
				return
			}
			if errors.Is(err, providers.ErrRateLimited) {
				http.Error(w, "rate limited", http.StatusTooManyRequests)
				return
			}
			http.Error(w, "failed to fetch subgroups", http.StatusInternalServerError)
			return
		}

		resp := GitLabGroupsResponse{
			Groups:      groups,
			TotalCount:  pageInfo.TotalCount,
			Page:        page,
			PageSize:    pageSize,
			HasNextPage: pageInfo.HasNextPage,
			NextPage:    pageInfo.NextPage,
		}
		_ = cache.SetJSON(r.Context(), c, cacheKey, resp, resolvePollTTL(r, store))
		writeJSON(w, http.StatusOK, resp)
	}
}

// GiteaReposResponse is the response for the Gitea repos endpoint.
type GiteaReposResponse struct {
	Repos       []providers.RepoData `json:"repos"`
	TotalCount  int                  `json:"total_count"`
	Page        int                  `json:"page"`
	PageSize    int                  `json:"page_size"`
	HasNextPage bool                 `json:"has_next_page"`
	NextPage    int                  `json:"next_page"`
}

// GiteaOrgsResponse is the response for the Gitea orgs endpoint.
type GiteaOrgsResponse struct {
	Orgs        []providers.OrgData `json:"orgs"`
	TotalCount  int                 `json:"total_count"`
	Page        int                 `json:"page"`
	PageSize    int                 `json:"page_size"`
	HasNextPage bool                `json:"has_next_page"`
	NextPage    int                 `json:"next_page"`
}

// GiteaReposHandler handles the Gitea repos endpoint.
// GET /api/providers/gitea/repos?base_url=https://gitea.example.com
// GET /api/providers/gitea/{owner}/repos?base_url=https://gitea.example.com
func GiteaReposHandler(authService *auth.Service, store *providerconfig.Store, c cache.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if requireAuth(w, r, authService) == nil {
			return
		}

		owner := r.PathValue("owner") // can be empty
		page, pageSize := parsePagination(r)
		baseURL := r.URL.Query().Get("base_url")

		if baseURL == "" {
			http.Error(w, "base_url is required for Gitea", http.StatusBadRequest)
			return
		}

		cacheKey := fmt.Sprintf("gitea:repos:%s:%s:p%d:ps%d", baseURL, owner, page, pageSize)
		if cached, ok, _ := cache.GetJSON[GiteaReposResponse](r.Context(), c, cacheKey); ok {
			writeJSON(w, http.StatusOK, cached)
			return
		}

		token, err := resolveProviderToken(r, store)
		if err != nil {
			http.Error(w, "failed to load provider token", http.StatusInternalServerError)
			return
		}

		client := providers.NewGiteaClient(baseURL, token)
		repos, pageInfo, err := client.ListPublicRepos(r.Context(), owner, providers.ListOptions{
			Page:     page,
			PageSize: pageSize,
		})
		if err != nil {
			log.Printf("Gitea API error for owner %q: %v", owner, err)
			if errors.Is(err, providers.ErrNotFound) {
				http.Error(w, "owner not found", http.StatusNotFound)
				return
			}
			if errors.Is(err, providers.ErrUnauthorized) {
				http.Error(w, "authentication required for this Gitea/Forgejo instance", http.StatusUnauthorized)
				return
			}
			if errors.Is(err, providers.ErrRateLimited) {
				http.Error(w, "rate limited", http.StatusTooManyRequests)
				return
			}
			http.Error(w, "failed to fetch repos", http.StatusInternalServerError)
			return
		}

		resp := GiteaReposResponse{
			Repos:       repos,
			TotalCount:  pageInfo.TotalCount,
			Page:        page,
			PageSize:    pageSize,
			HasNextPage: pageInfo.HasNextPage,
			NextPage:    pageInfo.NextPage,
		}
		_ = cache.SetJSON(r.Context(), c, cacheKey, resp, resolvePollTTL(r, store))
		writeJSON(w, http.StatusOK, resp)
	}
}

// GiteaOrgsHandler handles the Gitea orgs endpoint.
// GET /api/providers/gitea/orgs?base_url=https://gitea.example.com
func GiteaOrgsHandler(authService *auth.Service, store *providerconfig.Store, c cache.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if requireAuth(w, r, authService) == nil {
			return
		}

		page, pageSize := parsePagination(r)
		baseURL := r.URL.Query().Get("base_url")

		if baseURL == "" {
			http.Error(w, "base_url is required for Gitea", http.StatusBadRequest)
			return
		}

		cacheKey := fmt.Sprintf("gitea:orgs:%s:p%d:ps%d", baseURL, page, pageSize)
		if cached, ok, _ := cache.GetJSON[GiteaOrgsResponse](r.Context(), c, cacheKey); ok {
			writeJSON(w, http.StatusOK, cached)
			return
		}

		token, err := resolveProviderToken(r, store)
		if err != nil {
			http.Error(w, "failed to load provider token", http.StatusInternalServerError)
			return
		}

		client := providers.NewGiteaClient(baseURL, token)
		orgs, pageInfo, err := client.ListPublicOrgs(r.Context(), "", providers.ListOptions{
			Page:     page,
			PageSize: pageSize,
		})
		if err != nil {
			log.Printf("Gitea API error for orgs: %v", err)
			if errors.Is(err, providers.ErrUnauthorized) {
				http.Error(w, "authentication required for this Gitea/Forgejo instance", http.StatusUnauthorized)
				return
			}
			if errors.Is(err, providers.ErrRateLimited) {
				http.Error(w, "rate limited", http.StatusTooManyRequests)
				return
			}
			http.Error(w, "failed to fetch orgs", http.StatusInternalServerError)
			return
		}

		resp := GiteaOrgsResponse{
			Orgs:        orgs,
			TotalCount:  pageInfo.TotalCount,
			Page:        page,
			PageSize:    pageSize,
			HasNextPage: pageInfo.HasNextPage,
			NextPage:    pageInfo.NextPage,
		}
		_ = cache.SetJSON(r.Context(), c, cacheKey, resp, resolvePollTTL(r, store))
		writeJSON(w, http.StatusOK, resp)
	}
}

// DetectProviderResponse is the response for provider detection.
type DetectProviderResponse struct {
	Type    string `json:"type"`    // "gitlab", "gitea", "forgejo", or "unknown"
	Name    string `json:"name"`    // Friendly name derived from URL
	Version string `json:"version"` // Version if detected
}

// ProvidersDetectHandler probes a URL and detects the provider type.
// GET /api/providers/detect?url=https://gitlab.example.com
func ProvidersDetectHandler(authService *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if requireAuth(w, r, authService) == nil {
			return
		}

		baseURL := r.URL.Query().Get("url")
		if baseURL == "" {
			http.Error(w, "url is required", http.StatusBadRequest)
			return
		}

		// Normalize URL
		baseURL = strings.TrimSuffix(baseURL, "/")

		result := detectProviderType(r.Context(), baseURL)
		writeJSON(w, http.StatusOK, result)
	}
}

func detectProviderType(ctx context.Context, baseURL string) DetectProviderResponse {
	client := &http.Client{Timeout: 10 * time.Second}

	// Extract hostname for friendly name
	name := baseURL
	if strings.Contains(baseURL, "://") {
		parts := strings.SplitN(baseURL, "://", 2)
		if len(parts) > 1 {
			name = strings.Split(parts[1], "/")[0]
		}
	}

	// Try GitLab API first
	if resp := tryGitLabDetection(ctx, client, baseURL); resp != nil {
		resp.Name = name
		return *resp
	}

	// Try Gitea/Forgejo API
	if resp := tryGiteaDetection(ctx, client, baseURL); resp != nil {
		resp.Name = name
		return *resp
	}

	return DetectProviderResponse{
		Type: "unknown",
		Name: name,
	}
}

func tryGitLabDetection(ctx context.Context, client *http.Client, baseURL string) *DetectProviderResponse {
	// Try /api/v4/version endpoint
	url := baseURL + "/api/v4/version"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	// Check for GitLab-specific headers
	if resp.Header.Get("X-Gitlab-Meta") != "" || resp.StatusCode == http.StatusOK {
		return &DetectProviderResponse{
			Type: "gitlab",
		}
	}

	// Also check the main page for GitLab indicators
	req2, _ := http.NewRequestWithContext(ctx, http.MethodHead, baseURL, nil)
	if req2 != nil {
		resp2, err := client.Do(req2)
		if err == nil {
			defer resp2.Body.Close()
			if resp2.Header.Get("X-Gitlab-Meta") != "" {
				return &DetectProviderResponse{
					Type: "gitlab",
				}
			}
		}
	}

	return nil
}

func tryGiteaDetection(ctx context.Context, client *http.Client, baseURL string) *DetectProviderResponse {
	// Try /api/v1/version endpoint
	url := baseURL + "/api/v1/version"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil
	}

	// Check for Forgejo or Gitea headers/response
	if version := resp.Header.Get("X-Forgejo-Version"); version != "" {
		return &DetectProviderResponse{
			Type:    "forgejo",
			Version: version,
		}
	}

	if version := resp.Header.Get("X-Gitea-Version"); version != "" {
		return &DetectProviderResponse{
			Type:    "gitea",
			Version: version,
		}
	}

	// If we got a 200 from /api/v1/version, it's likely Gitea-compatible
	return &DetectProviderResponse{
		Type: "gitea",
	}
}

// RepoDetailsResponse is the response for repo details endpoint.
type RepoDetailsResponse struct {
	Details      *providers.RepoDetails      `json:"details"`
	Readme       string                      `json:"readme"`
	Commits      []providers.CommitInfo       `json:"commits,omitempty"`
	Contributors []providers.ContributorInfo  `json:"contributors,omitempty"`
}

// enrichContributors fills in missing contributor data from commits and generates
// Gravatar avatar URLs for contributors without an avatar.
func enrichContributors(contributors []providers.ContributorInfo, commits []providers.CommitInfo) []providers.ContributorInfo {
	if len(contributors) == 0 {
		return contributors
	}

	// Build lookup maps from commits
	emailByLogin := make(map[string]string)
	avatarByLogin := make(map[string]string)
	emailByName := make(map[string]string)
	avatarByEmail := make(map[string]string)

	for _, c := range commits {
		email := strings.ToLower(strings.TrimSpace(c.AuthorEmail))
		if c.AuthorLogin != "" && email != "" {
			if _, ok := emailByLogin[c.AuthorLogin]; !ok {
				emailByLogin[c.AuthorLogin] = email
			}
		}
		if c.AuthorLogin != "" && c.AuthorAvatar != "" {
			if _, ok := avatarByLogin[c.AuthorLogin]; !ok {
				avatarByLogin[c.AuthorLogin] = c.AuthorAvatar
			}
		}
		if c.AuthorName != "" && email != "" {
			if _, ok := emailByName[c.AuthorName]; !ok {
				emailByName[c.AuthorName] = email
			}
		}
		if email != "" && c.AuthorAvatar != "" {
			if _, ok := avatarByEmail[email]; !ok {
				avatarByEmail[email] = c.AuthorAvatar
			}
		}
	}

	for i := range contributors {
		c := &contributors[i]

		// Normalize existing email
		c.Email = strings.ToLower(strings.TrimSpace(c.Email))

		// Fill in missing email from commits
		if c.Email == "" {
			if c.Login != "" {
				if email, ok := emailByLogin[c.Login]; ok {
					c.Email = email
				}
			}
			if c.Email == "" && c.Name != "" {
				if email, ok := emailByName[c.Name]; ok {
					c.Email = email
				}
			}
		}

		// Fill in missing avatar: try commit data first, then Gravatar
		if c.AvatarURL == "" {
			if c.Login != "" {
				if avatar, ok := avatarByLogin[c.Login]; ok {
					c.AvatarURL = avatar
				}
			}
			if c.AvatarURL == "" && c.Email != "" {
				if avatar, ok := avatarByEmail[c.Email]; ok {
					c.AvatarURL = avatar
				}
			}
			// Fallback to Gravatar when the provider API did not supply an avatar URL.
			// Note: this sends an MD5 hash of the contributor's email address to
			// gravatar.com (a third party). For air-gapped or privacy-sensitive
			// deployments, consider disabling this via a configuration option.
			if c.AvatarURL == "" && c.Email != "" {
				hash := md5.Sum([]byte(c.Email))
				c.AvatarURL = fmt.Sprintf("https://www.gravatar.com/avatar/%x?d=identicon&s=80", hash)
			}
		}
	}

	return contributors
}

// enrichCommits fills in missing commit author avatars from the enriched contributors list.
func enrichCommits(commits []providers.CommitInfo, contributors []providers.ContributorInfo) []providers.CommitInfo {
	if len(commits) == 0 || len(contributors) == 0 {
		return commits
	}

	avatarByLogin := make(map[string]string)
	avatarByEmail := make(map[string]string)
	avatarByName := make(map[string]string)

	for _, c := range contributors {
		if c.AvatarURL == "" {
			continue
		}
		if c.Login != "" {
			avatarByLogin[c.Login] = c.AvatarURL
		}
		if c.Email != "" {
			avatarByEmail[strings.ToLower(strings.TrimSpace(c.Email))] = c.AvatarURL
		}
		if c.Name != "" {
			avatarByName[c.Name] = c.AvatarURL
		}
	}

	for i := range commits {
		c := &commits[i]
		if c.AuthorAvatar != "" {
			continue
		}
		if c.AuthorLogin != "" {
			if avatar, ok := avatarByLogin[c.AuthorLogin]; ok {
				c.AuthorAvatar = avatar
				continue
			}
		}
		if c.AuthorEmail != "" {
			if avatar, ok := avatarByEmail[strings.ToLower(strings.TrimSpace(c.AuthorEmail))]; ok {
				c.AuthorAvatar = avatar
				continue
			}
		}
		if c.AuthorName != "" {
			if avatar, ok := avatarByName[c.AuthorName]; ok {
				c.AuthorAvatar = avatar
			}
		}
	}

	return commits
}

// GitHubRepoDetailsHandler handles fetching GitHub repo details.
// GET /api/providers/github/{owner}/{repo}/details
func GitHubRepoDetailsHandler(authService *auth.Service, store *providerconfig.Store, c cache.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if requireAuth(w, r, authService) == nil {
			return
		}

		owner := r.PathValue("owner")
		repo := r.PathValue("repo")
		if owner == "" || repo == "" {
			http.Error(w, "owner and repo are required", http.StatusBadRequest)
			return
		}

		token, err := resolveProviderToken(r, store)
		if err != nil {
			http.Error(w, "failed to load provider token", http.StatusInternalServerError)
			return
		}

		client := providers.NewGitHubClient("", token)

		details, err := client.GetRepoDetails(r.Context(), owner, repo)
		if err != nil {
			log.Printf("GitHub repo details error for %s/%s: %v", owner, repo, err)
			if errors.Is(err, providers.ErrNotFound) {
				http.Error(w, "repository not found", http.StatusNotFound)
				return
			}
			if errors.Is(err, providers.ErrUnauthorized) {
				http.Error(w, "authentication required for this GitHub repo", http.StatusUnauthorized)
				return
			}
			http.Error(w, "failed to fetch repo details", http.StatusInternalServerError)
			return
		}

		// Fetch readme, commits, and contributors in parallel
		var readme string
		var commits []providers.CommitInfo
		var contributors []providers.ContributorInfo
		var wg sync.WaitGroup

		wg.Add(3)
		go func() {
			defer wg.Done()
			var err error
			readme, err = client.GetReadme(r.Context(), owner, repo)
			if err != nil {
				log.Printf("GitHub README error for %s/%s: %v", owner, repo, err)
			}
		}()
		go func() {
			defer wg.Done()
			var err error
			commits, err = client.GetCommitLog(r.Context(), owner, repo, 20)
			if err != nil {
				log.Printf("GitHub commits error for %s/%s: %v", owner, repo, err)
			}
		}()
		go func() {
			defer wg.Done()
			repoPath := owner + "/" + repo
			cacheKey := fmt.Sprintf("contributors:github:%s", repoPath)
			if cached, ok, _ := cache.GetJSON[[]providers.ContributorInfo](r.Context(), c, cacheKey); ok {
				contributors = cached
				return
			}
			var err error
			contributors, err = client.GetContributors(r.Context(), repoPath, 30)
			if err != nil {
				log.Printf("GitHub contributors error for %s/%s: %v", owner, repo, err)
				return
			}
			_ = cache.SetJSON(r.Context(), c, cacheKey, contributors, contributorCacheTTL)
		}()
		wg.Wait()

		contributors = enrichContributors(contributors, commits)
		commits = enrichCommits(commits, contributors)

		writeJSON(w, http.StatusOK, RepoDetailsResponse{
			Details:      details,
			Readme:       readme,
			Commits:      commits,
			Contributors: contributors,
		})
	}
}

// GitLabRepoDetailsHandler handles fetching GitLab project details.
// GET /api/providers/gitlab/{projectPath}/details?base_url=...
func GitLabRepoDetailsHandler(authService *auth.Service, store *providerconfig.Store, c cache.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if requireAuth(w, r, authService) == nil {
			return
		}

		projectPath := r.PathValue("projectPath")
		if projectPath == "" {
			http.Error(w, "projectPath is required", http.StatusBadRequest)
			return
		}

		// URL-decode the path since it may contain encoded slashes (%2F)
		if decoded, err := url.PathUnescape(projectPath); err == nil {
			projectPath = decoded
		}

		baseURL := r.URL.Query().Get("base_url")
		token, err := resolveProviderTokenByBaseURL(r, store, providerconfig.ProviderGitLab, projectPath)
		if err != nil {
			http.Error(w, "failed to load provider token", http.StatusInternalServerError)
			return
		}

		client := providers.NewGitLabClient(baseURL, token)

		details, err := client.GetRepoDetails(r.Context(), projectPath)
		if err != nil {
			log.Printf("GitLab project details error for %q (base_url=%q): %v", projectPath, baseURL, err)
			if errors.Is(err, providers.ErrNotFound) {
				// Could be missing or may require authentication for private instances
				http.Error(w, "project not found (may require authentication for private instances)", http.StatusNotFound)
				return
			}
			if errors.Is(err, providers.ErrUnauthorized) {
				http.Error(w, "authentication required for this GitLab instance", http.StatusUnauthorized)
				return
			}
			http.Error(w, "failed to fetch project details", http.StatusInternalServerError)
			return
		}

		// Fetch readme, commits, and contributors in parallel
		var readme string
		var commits []providers.CommitInfo
		var contributors []providers.ContributorInfo
		var wg sync.WaitGroup

		wg.Add(3)
		go func() {
			defer wg.Done()
			var err error
			readme, err = client.GetReadme(r.Context(), projectPath)
			if err != nil {
				log.Printf("GitLab README error for %s: %v", projectPath, err)
			}
		}()
		go func() {
			defer wg.Done()
			var err error
			commits, err = client.GetCommitLog(r.Context(), projectPath, 20)
			if err != nil {
				log.Printf("GitLab commits error for %s: %v", projectPath, err)
			}
		}()
		go func() {
			defer wg.Done()
			cacheKey := fmt.Sprintf("contributors:gitlab:%s", projectPath)
			if cached, ok, _ := cache.GetJSON[[]providers.ContributorInfo](r.Context(), c, cacheKey); ok {
				contributors = cached
				return
			}
			var err error
			contributors, err = client.GetContributors(r.Context(), projectPath, 30)
			if err != nil {
				log.Printf("GitLab contributors error for %s: %v", projectPath, err)
				return
			}
			_ = cache.SetJSON(r.Context(), c, cacheKey, contributors, contributorCacheTTL)
		}()
		wg.Wait()

		contributors = enrichContributors(contributors, commits)
		commits = enrichCommits(commits, contributors)

		writeJSON(w, http.StatusOK, RepoDetailsResponse{
			Details:      details,
			Readme:       readme,
			Commits:      commits,
			Contributors: contributors,
		})
	}
}

// GiteaRepoDetailsHandler handles fetching Gitea repo details.
// GET /api/providers/gitea/{owner}/{repo}/details?base_url=...
func GiteaRepoDetailsHandler(authService *auth.Service, store *providerconfig.Store, c cache.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if requireAuth(w, r, authService) == nil {
			return
		}

		owner := r.PathValue("owner")
		repo := r.PathValue("repo")
		if owner == "" || repo == "" {
			http.Error(w, "owner and repo are required", http.StatusBadRequest)
			return
		}

		baseURL := r.URL.Query().Get("base_url")
		if baseURL == "" {
			http.Error(w, "base_url is required for Gitea", http.StatusBadRequest)
			return
		}

		token, err := resolveProviderTokenByBaseURL(r, store, providerconfig.ProviderGitea, owner+"/"+repo)
		if err != nil {
			http.Error(w, "failed to load provider token", http.StatusInternalServerError)
			return
		}

		client := providers.NewGiteaClient(baseURL, token)

		details, err := client.GetRepoDetails(r.Context(), owner, repo)
		if err != nil {
			log.Printf("Gitea repo details error for %s/%s: %v", owner, repo, err)
			if errors.Is(err, providers.ErrNotFound) {
				http.Error(w, "repository not found", http.StatusNotFound)
				return
			}
			if errors.Is(err, providers.ErrUnauthorized) {
				http.Error(w, "authentication required for this Gitea/Forgejo repo", http.StatusUnauthorized)
				return
			}
			http.Error(w, "failed to fetch repo details", http.StatusInternalServerError)
			return
		}

		// Fetch readme, commits, and contributors in parallel
		var readme string
		var commits []providers.CommitInfo
		var contributors []providers.ContributorInfo
		var wg sync.WaitGroup

		wg.Add(3)
		go func() {
			defer wg.Done()
			readme, _ = client.GetReadme(r.Context(), owner, repo)
		}()
		go func() {
			defer wg.Done()
			var err error
			commits, err = client.GetCommitLog(r.Context(), owner, repo, 20)
			if err != nil {
				log.Printf("Gitea commits error for %s/%s: %v", owner, repo, err)
			}
		}()
		go func() {
			defer wg.Done()
			repoPath := owner + "/" + repo
			cacheKey := fmt.Sprintf("contributors:gitea:%s", repoPath)
			if cached, ok, _ := cache.GetJSON[[]providers.ContributorInfo](r.Context(), c, cacheKey); ok {
				contributors = cached
				return
			}
			var err error
			contributors, err = client.GetContributors(r.Context(), repoPath, 30)
			if err != nil {
				log.Printf("Gitea contributors error for %s/%s: %v", owner, repo, err)
				return
			}
			_ = cache.SetJSON(r.Context(), c, cacheKey, contributors, contributorCacheTTL)
		}()
		wg.Wait()

		contributors = enrichContributors(contributors, commits)
		commits = enrichCommits(commits, contributors)

		writeJSON(w, http.StatusOK, RepoDetailsResponse{
			Details:      details,
			Readme:       readme,
			Commits:      commits,
			Contributors: contributors,
		})
	}
}

// sortRepos sorts a slice of RepoData by the specified column and order.
func sortRepos(repos []providers.RepoData, sortColumn, sortOrder string) {
	if sortColumn == "" || len(repos) == 0 {
		return
	}

	// Default to ascending if order is not specified or invalid
	ascending := sortOrder != "desc"

	switch sortColumn {
	case "name":
		sortByName(repos, ascending)
	case "language":
		sortByLanguage(repos, ascending)
	case "updated", "updated_at":
		sortByUpdated(repos, ascending)
	case "path", "full_path":
		sortByPath(repos, ascending)
	}
}

func sortByName(repos []providers.RepoData, ascending bool) {
	for i := 0; i < len(repos)-1; i++ {
		for j := i + 1; j < len(repos); j++ {
			swap := false
			if ascending {
				swap = repos[i].Name > repos[j].Name
			} else {
				swap = repos[i].Name < repos[j].Name
			}
			if swap {
				repos[i], repos[j] = repos[j], repos[i]
			}
		}
	}
}

func sortByLanguage(repos []providers.RepoData, ascending bool) {
	// Helper to get primary language (first in array)
	getPrimary := func(langs []string) string {
		if len(langs) > 0 {
			return langs[0]
		}
		return ""
	}

	for i := 0; i < len(repos)-1; i++ {
		for j := i + 1; j < len(repos); j++ {
			swap := false
			langI := getPrimary(repos[i].Languages)
			langJ := getPrimary(repos[j].Languages)
			if ascending {
				swap = langI > langJ
			} else {
				swap = langI < langJ
			}
			if swap {
				repos[i], repos[j] = repos[j], repos[i]
			}
		}
	}
}

func sortByUpdated(repos []providers.RepoData, ascending bool) {
	for i := 0; i < len(repos)-1; i++ {
		for j := i + 1; j < len(repos); j++ {
			swap := false
			if ascending {
				swap = repos[i].UpdatedAt.Before(repos[j].UpdatedAt)
			} else {
				swap = repos[i].UpdatedAt.After(repos[j].UpdatedAt)
			}
			if swap {
				repos[i], repos[j] = repos[j], repos[i]
			}
		}
	}
}

func sortByPath(repos []providers.RepoData, ascending bool) {
	for i := 0; i < len(repos)-1; i++ {
		for j := i + 1; j < len(repos); j++ {
			swap := false
			if ascending {
				swap = repos[i].FullPath > repos[j].FullPath
			} else {
				swap = repos[i].FullPath < repos[j].FullPath
			}
			if swap {
				repos[i], repos[j] = repos[j], repos[i]
			}
		}
	}
}
