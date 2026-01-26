package uiapi

import (
	"errors"
	"log"
	"net/http"

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
// GET /api/providers/gitlab/{group}/projects
func GitLabProjectsHandler(authService *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if authService != nil {
			if _, err := authService.LoadSession(r); err != nil {
				http.Error(w, "unauthenticated", http.StatusUnauthorized)
				return
			}
		}

		group := r.PathValue("group")
		if group == "" {
			http.Error(w, "group is required", http.StatusBadRequest)
			return
		}

		page, pageSize := parsePagination(r)
		includeSubgroups := r.URL.Query().Get("include_subgroups") == "true"

		client := providers.NewGitLabClient("", "")
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
// GET /api/providers/gitlab/{group}/subgroups
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

		client := providers.NewGitLabClient("", "")
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
