package server

import (
	"net/http"
	"time"

	"github.com/NorskHelsenett/spam/internal/auth"
	"github.com/NorskHelsenett/spam/internal/events"
	"github.com/NorskHelsenett/spam/internal/handlers/health"
	"github.com/NorskHelsenett/spam/internal/runner"
	"github.com/NorskHelsenett/spam/internal/uiapi"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"gorm.io/gorm"
)

// RouterOptions contains optional dependencies for the router.
type RouterOptions struct {
	K8sClient   *runner.K8sClient
	RunExecutor *runner.RunExecutor
}

// NewRouter wires the HTTP routes and middleware for the API server.
func NewRouter(db *gorm.DB, authService *auth.Service, shutdown <-chan struct{}, opts *RouterOptions) http.Handler {
	r := chi.NewRouter()

	// Health check endpoint without middleware to avoid noise in logs
	r.Get("/api/healthz", health.Handler(db))

	// Apply middleware to all other routes
	r.Group(func(r chi.Router) {
		r.Use(middleware.RequestID)
		r.Use(middleware.RealIP)
		r.Use(middleware.Logger)
		r.Use(middleware.Recoverer)
		r.Use(middleware.Timeout(60 * time.Second))

		r.Route("/api", func(api chi.Router) {
			if authService != nil {
				api.Route("/auth", func(authRouter chi.Router) {
					authRouter.Get("/login", authService.LoginHandler())
					authRouter.Get("/callback", authService.CallbackHandler())
					authRouter.Get("/me", authService.MeHandler())
					authRouter.Post("/logout", authService.LogoutHandler())
				})
				api.Get("/auth/pending/stream", events.PendingApprovalStream(authService.PendingSessionInfo, authService.UserApprovalStatus))
				api.Get("/app/stream", events.AppStreamHandler(authService.SessionInfo, shutdown))
				api.Post("/sboms/upload", uiapi.SBOMUploadHandler(db, authService))
				api.Get("/sboms/{id}/download", uiapi.SBOMDownloadHandler(db, authService))
				api.Get("/admin/users", uiapi.AdminUsersListHandler(db, authService))
				api.Patch("/admin/users/{userID}", uiapi.AdminUserRoleHandler(db, authService))

				// Stats
				api.Get("/stats", uiapi.StatsHandler(db, authService))

				// Component search and detail
				api.Get("/components", uiapi.ComponentsListHandler(db, authService))
				api.Get("/components/ecosystems", uiapi.EcosystemsListHandler(db, authService))
				api.Get("/components/{componentID}", uiapi.ComponentDetailHandler(db, authService))
				api.Get("/components/{componentID}/assets", uiapi.ComponentAssetsHandler(db, authService))

				// Manifest endpoints
				api.Get("/manifests", uiapi.ManifestsListHandler(db, authService))
				api.Get("/manifests/{id}", uiapi.ManifestGetHandler(db, authService))
				api.Get("/dependencies/search", uiapi.DependencySearchHandler(db, authService))

				// Unified dependencies (SBOM + Manifest merged view)
				api.Get("/dependencies", uiapi.UnifiedDependenciesHandler(db, authService))
				api.Get("/dependencies/detail", uiapi.DependencyDetailHandler(db, authService))
				api.Get("/dependencies/assets", uiapi.DependencyAssetsHandler(db, authService))
				api.Get("/repos/security", uiapi.RepoSecurityCountsHandler(db, authService))
				api.Get("/repos/metadata", uiapi.RepoMetadataHandler(db, authService))
				api.Get("/providers/detect", uiapi.ProvidersDetectHandler(authService))
				api.Get("/providers/github/{owner}/repos", uiapi.GitHubReposHandler(authService))
				api.Get("/providers/github/{owner}/{repo}/details", uiapi.GitHubRepoDetailsHandler(authService))
				api.Get("/providers/gitlab/projects", uiapi.GitLabProjectsHandler(authService))
				api.Get("/providers/gitlab/{group}/projects", uiapi.GitLabProjectsHandler(authService))
				api.Get("/providers/gitlab/subgroups", uiapi.GitLabSubgroupsHandler(authService))
				api.Get("/providers/gitlab/{group}/subgroups", uiapi.GitLabSubgroupsHandler(authService))
				api.Get("/providers/gitlab/{projectPath}/details", uiapi.GitLabRepoDetailsHandler(authService))
				api.Get("/providers/gitea/repos", uiapi.GiteaReposHandler(authService))
				api.Get("/providers/gitea/{owner}/repos", uiapi.GiteaReposHandler(authService))
				api.Get("/providers/gitea/orgs", uiapi.GiteaOrgsHandler(authService))
				api.Get("/providers/gitea/{owner}/{repo}/details", uiapi.GiteaRepoDetailsHandler(authService))

				// Runs endpoints
				api.Get("/runs", uiapi.RunsListHandler(db, authService))
				api.Post("/runs", uiapi.RunsCreateHandler(db, authService))
				api.Get("/runs/{id}", uiapi.RunGetHandler(db, authService))
				api.Get("/runs/{id}/stream", uiapi.RunStreamHandler(db, authService))
				api.Get("/runs/{id}/secrets", uiapi.RunSecretsHandler(db, authService))

				// Kubernetes integration endpoints (only available if runner is enabled)
				if opts != nil && opts.K8sClient != nil {
					api.Get("/runs/{id}/k8s-logs", uiapi.RunLogsHandler(db, authService, opts.K8sClient))
					api.Get("/runs/{id}/k8s-status", uiapi.RunJobStatusHandler(db, authService, opts.K8sClient))
				}
				if opts != nil && opts.RunExecutor != nil {
					api.Post("/runs/{id}/cancel", uiapi.RunCancelHandler(db, authService, opts.RunExecutor))
				}
			}
		})

		if spaHandler != nil {
			r.Handle("/*", spaHandler)
		}
	})

	return r
}
