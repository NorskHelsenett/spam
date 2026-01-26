package uiapi

import (
	"context"
	"errors"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/NorskHelsenett/spam/internal/auth"
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

// GitHubReposHandler handles the GitHub repos endpoint.
// GET /api/providers/github/{owner}/repos
func GitHubReposHandler(authService *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if authService != nil {
			if _, err := authService.LoadSession(r); err != nil {
				http.Error(w, "unauthenticated", http.StatusUnauthorized)
				return
			}
		}

		owner := r.PathValue("owner")
		if owner == "" {
			http.Error(w, "owner is required", http.StatusBadRequest)
			return
		}

		page, pageSize := parsePagination(r)

		client := providers.NewGitHubClient("", "")
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
			if errors.Is(err, providers.ErrRateLimited) {
				http.Error(w, "rate limited", http.StatusTooManyRequests)
				return
			}
			http.Error(w, "failed to fetch repos", http.StatusInternalServerError)
			return
		}

		writeJSON(w, http.StatusOK, GitHubReposResponse{
			Repos:       repos,
			TotalCount:  pageInfo.TotalCount,
			Page:        page,
			PageSize:    pageSize,
			HasNextPage: pageInfo.HasNextPage,
			NextPage:    pageInfo.NextPage,
		})
	}
}

// GitLabProjectsHandler handles the GitLab projects endpoint.
// GET /api/providers/gitlab/{group}/projects?base_url=https://gitlab.example.com
func GitLabProjectsHandler(authService *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if authService != nil {
			if _, err := authService.LoadSession(r); err != nil {
				http.Error(w, "unauthenticated", http.StatusUnauthorized)
				return
			}
		}

		group := r.PathValue("group")
		// group can be empty to list all public projects

		page, pageSize := parsePagination(r)
		includeSubgroups := r.URL.Query().Get("include_subgroups") == "true"
		baseURL := r.URL.Query().Get("base_url") // Custom instance URL

		client := providers.NewGitLabClient(baseURL, "")
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
			if errors.Is(err, providers.ErrRateLimited) {
				http.Error(w, "rate limited", http.StatusTooManyRequests)
				return
			}
			http.Error(w, "failed to fetch projects", http.StatusInternalServerError)
			return
		}

		writeJSON(w, http.StatusOK, GitLabProjectsResponse{
			Projects:    projects,
			TotalCount:  pageInfo.TotalCount,
			Page:        page,
			PageSize:    pageSize,
			HasNextPage: pageInfo.HasNextPage,
			NextPage:    pageInfo.NextPage,
		})
	}
}

// GitLabSubgroupsHandler handles the GitLab subgroups endpoint.
// GET /api/providers/gitlab/{group}/subgroups?base_url=https://gitlab.example.com
func GitLabSubgroupsHandler(authService *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if authService != nil {
			if _, err := authService.LoadSession(r); err != nil {
				http.Error(w, "unauthenticated", http.StatusUnauthorized)
				return
			}
		}

		group := r.PathValue("group")
		// group can be empty for top-level groups

		page, pageSize := parsePagination(r)
		baseURL := r.URL.Query().Get("base_url") // Custom instance URL

		client := providers.NewGitLabClient(baseURL, "")
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
			if errors.Is(err, providers.ErrRateLimited) {
				http.Error(w, "rate limited", http.StatusTooManyRequests)
				return
			}
			http.Error(w, "failed to fetch subgroups", http.StatusInternalServerError)
			return
		}

		writeJSON(w, http.StatusOK, GitLabGroupsResponse{
			Groups:      groups,
			TotalCount:  pageInfo.TotalCount,
			Page:        page,
			PageSize:    pageSize,
			HasNextPage: pageInfo.HasNextPage,
			NextPage:    pageInfo.NextPage,
		})
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
func GiteaReposHandler(authService *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if authService != nil {
			if _, err := authService.LoadSession(r); err != nil {
				http.Error(w, "unauthenticated", http.StatusUnauthorized)
				return
			}
		}

		owner := r.PathValue("owner") // can be empty
		page, pageSize := parsePagination(r)
		baseURL := r.URL.Query().Get("base_url")

		if baseURL == "" {
			http.Error(w, "base_url is required for Gitea", http.StatusBadRequest)
			return
		}

		client := providers.NewGiteaClient(baseURL, "")
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
			if errors.Is(err, providers.ErrRateLimited) {
				http.Error(w, "rate limited", http.StatusTooManyRequests)
				return
			}
			http.Error(w, "failed to fetch repos", http.StatusInternalServerError)
			return
		}

		writeJSON(w, http.StatusOK, GiteaReposResponse{
			Repos:       repos,
			TotalCount:  pageInfo.TotalCount,
			Page:        page,
			PageSize:    pageSize,
			HasNextPage: pageInfo.HasNextPage,
			NextPage:    pageInfo.NextPage,
		})
	}
}

// GiteaOrgsHandler handles the Gitea orgs endpoint.
// GET /api/providers/gitea/orgs?base_url=https://gitea.example.com
func GiteaOrgsHandler(authService *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if authService != nil {
			if _, err := authService.LoadSession(r); err != nil {
				http.Error(w, "unauthenticated", http.StatusUnauthorized)
				return
			}
		}

		page, pageSize := parsePagination(r)
		baseURL := r.URL.Query().Get("base_url")

		if baseURL == "" {
			http.Error(w, "base_url is required for Gitea", http.StatusBadRequest)
			return
		}

		client := providers.NewGiteaClient(baseURL, "")
		orgs, pageInfo, err := client.ListPublicOrgs(r.Context(), "", providers.ListOptions{
			Page:     page,
			PageSize: pageSize,
		})
		if err != nil {
			log.Printf("Gitea API error for orgs: %v", err)
			if errors.Is(err, providers.ErrRateLimited) {
				http.Error(w, "rate limited", http.StatusTooManyRequests)
				return
			}
			http.Error(w, "failed to fetch orgs", http.StatusInternalServerError)
			return
		}

		writeJSON(w, http.StatusOK, GiteaOrgsResponse{
			Orgs:        orgs,
			TotalCount:  pageInfo.TotalCount,
			Page:        page,
			PageSize:    pageSize,
			HasNextPage: pageInfo.HasNextPage,
			NextPage:    pageInfo.NextPage,
		})
	}
}

// DetectProviderResponse is the response for provider detection.
type DetectProviderResponse struct {
	Type    string `json:"type"`    // "gitlab", "gitea", "forgejo", or "unknown"
	Name    string `json:"name"`    // Friendly name derived from URL
	Version string `json:"version"` // Version if detected
}

// DetectProviderHandler probes a URL and detects the provider type.
// GET /api/providers/detect?url=https://gitlab.example.com
func DetectProviderHandler(authService *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if authService != nil {
			if _, err := authService.LoadSession(r); err != nil {
				http.Error(w, "unauthenticated", http.StatusUnauthorized)
				return
			}
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
	Details *providers.RepoDetails `json:"details"`
	Readme  string                 `json:"readme"`
}

// GitHubRepoDetailsHandler handles fetching GitHub repo details.
// GET /api/providers/github/{owner}/{repo}/details
func GitHubRepoDetailsHandler(authService *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if authService != nil {
			if _, err := authService.LoadSession(r); err != nil {
				http.Error(w, "unauthenticated", http.StatusUnauthorized)
				return
			}
		}

		owner := r.PathValue("owner")
		repo := r.PathValue("repo")
		if owner == "" || repo == "" {
			http.Error(w, "owner and repo are required", http.StatusBadRequest)
			return
		}

		client := providers.NewGitHubClient("", "")

		details, err := client.GetRepoDetails(r.Context(), owner, repo)
		if err != nil {
			log.Printf("GitHub repo details error for %s/%s: %v", owner, repo, err)
			if errors.Is(err, providers.ErrNotFound) {
				http.Error(w, "repository not found", http.StatusNotFound)
				return
			}
			http.Error(w, "failed to fetch repo details", http.StatusInternalServerError)
			return
		}

		readme, readmeErr := client.GetReadme(r.Context(), owner, repo)
		if readmeErr != nil {
			log.Printf("GitHub README error for %s/%s: %v", owner, repo, readmeErr)
		}

		writeJSON(w, http.StatusOK, RepoDetailsResponse{
			Details: details,
			Readme:  readme,
		})
	}
}

// GitLabRepoDetailsHandler handles fetching GitLab project details.
// GET /api/providers/gitlab/{projectPath}/details?base_url=...
func GitLabRepoDetailsHandler(authService *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if authService != nil {
			if _, err := authService.LoadSession(r); err != nil {
				http.Error(w, "unauthenticated", http.StatusUnauthorized)
				return
			}
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
		client := providers.NewGitLabClient(baseURL, "")

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

		readme, readmeErr := client.GetReadme(r.Context(), projectPath)
		if readmeErr != nil {
			log.Printf("GitLab README error for %s: %v", projectPath, readmeErr)
		}

		writeJSON(w, http.StatusOK, RepoDetailsResponse{
			Details: details,
			Readme:  readme,
		})
	}
}

// GiteaRepoDetailsHandler handles fetching Gitea repo details.
// GET /api/providers/gitea/{owner}/{repo}/details?base_url=...
func GiteaRepoDetailsHandler(authService *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if authService != nil {
			if _, err := authService.LoadSession(r); err != nil {
				http.Error(w, "unauthenticated", http.StatusUnauthorized)
				return
			}
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

		client := providers.NewGiteaClient(baseURL, "")

		details, err := client.GetRepoDetails(r.Context(), owner, repo)
		if err != nil {
			log.Printf("Gitea repo details error for %s/%s: %v", owner, repo, err)
			if errors.Is(err, providers.ErrNotFound) {
				http.Error(w, "repository not found", http.StatusNotFound)
				return
			}
			http.Error(w, "failed to fetch repo details", http.StatusInternalServerError)
			return
		}

		readme, _ := client.GetReadme(r.Context(), owner, repo)

		writeJSON(w, http.StatusOK, RepoDetailsResponse{
			Details: details,
			Readme:  readme,
		})
	}
}
