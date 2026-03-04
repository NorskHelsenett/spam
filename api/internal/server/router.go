package server

import (
	"net/http"
	"time"

	"github.com/NorskHelsenett/spam/internal/auth"
	"github.com/NorskHelsenett/spam/internal/cache"
	"github.com/NorskHelsenett/spam/internal/events"
	"github.com/NorskHelsenett/spam/internal/handlers/health"
	"github.com/NorskHelsenett/spam/internal/providerconfig"
	"github.com/NorskHelsenett/spam/internal/runner"
	"github.com/NorskHelsenett/spam/internal/uiapi"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"gorm.io/gorm"
)

// RouterOptions contains optional dependencies for the router.
type RouterOptions struct {
	K8sClient     *runner.K8sClient
	RunExecutor   *runner.RunExecutor
	ProviderStore *providerconfig.Store
	Cache         cache.Store
}

// NewRouter wires the HTTP routes and middleware for the API server.
func NewRouter(db *gorm.DB, authService *auth.Service, shutdown <-chan struct{}, opts *RouterOptions) http.Handler {
	r := chi.NewRouter()
	var providerStore *providerconfig.Store
	var appCache cache.Store
	if opts != nil {
		providerStore = opts.ProviderStore
		appCache = opts.Cache
	}
	if appCache == nil {
		appCache = cache.NewMemory()
	}

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
				api.Get("/sboms/{id}", uiapi.SBOMGetHandler(db, authService))
				api.Get("/sboms/{id}/download", uiapi.SBOMDownloadHandler(db, authService))
				api.Get("/admin/users", uiapi.AdminUsersListHandler(db, authService))
				api.Patch("/admin/users/{userID}", uiapi.AdminUserRoleHandler(db, authService))
				api.Get("/admin/providers", uiapi.AdminProvidersListHandler(authService, providerStore))
				api.Post("/admin/providers", uiapi.AdminProvidersCreateHandler(authService, providerStore))
				api.Patch("/admin/providers/{id}", uiapi.AdminProvidersUpdateHandler(authService, providerStore))
				api.Post("/admin/providers/{id}/rotate", uiapi.AdminProvidersRotateHandler(authService, providerStore))
				api.Post("/admin/providers/{id}/sync", uiapi.AdminProvidersSyncHandler(db, authService, providerStore))
				api.Delete("/admin/providers/{id}", uiapi.AdminProvidersDeleteHandler(authService, providerStore))
				api.Post("/admin/views/refresh", uiapi.AdminViewsRefreshHandler(db, authService))
				api.Get("/admin/views/status", uiapi.AdminViewsStatusHandler(db, authService))

				// Stats
				api.Get("/stats", uiapi.StatsHandler(db, authService))
				api.Get("/app/summary", uiapi.AppSummaryHandler(db, authService, appCache))

				// Ecosystems endpoint
				api.Get("/components/ecosystems", uiapi.EcosystemsListHandler(db, authService))

				// Manifest endpoints
				api.Get("/manifests", uiapi.ManifestsListHandler(db, authService))
				api.Get("/manifests/{id}", uiapi.ManifestGetHandler(db, authService))
				api.Get("/dependencies/search", uiapi.DependencySearchHandler(db, authService))

				// Unified dependencies (SBOM + Manifest merged view)
				api.Get("/dependencies", uiapi.UnifiedDependenciesHandler(db, authService))
				api.Get("/dependencies/export.csv", uiapi.DependencyExportCSVHandler(db, authService))
				api.Get("/dependencies/detail", uiapi.DependencyDetailHandler(db, authService))
				api.Get("/dependencies/assets", uiapi.DependencyAssetsHandler(db, authService))
				api.Get("/repos/search", uiapi.RepoSearchHandler(db, authService))
				api.Get("/repos/contributors", uiapi.RepoContributorsHandler(db, authService, providerStore, appCache))
				api.Get("/repos/security", uiapi.RepoSecurityCountsHandler(db, authService))
				api.Get("/repos/metadata", uiapi.RepoMetadataHandler(db, authService, appCache))
				api.Get("/providers/instances", uiapi.ProvidersInstancesHandler(db, authService, providerStore))
				api.Get("/providers/details", uiapi.ProviderRepoDetailsHandler(authService, providerStore, db, appCache))
				api.Get("/providers/detect", uiapi.ProvidersDetectHandler(authService))
				api.Get("/providers/github/{owner}/repos", uiapi.GitHubReposHandler(authService, providerStore, appCache, db))
				api.Get("/providers/github/{owner}/{repo}/details", uiapi.GitHubRepoDetailsHandler(authService, providerStore, appCache))
				api.Get("/providers/gitlab/projects", uiapi.GitLabProjectsHandler(authService, providerStore, appCache, db))
				api.Get("/providers/gitlab/{group}/projects", uiapi.GitLabProjectsHandler(authService, providerStore, appCache, db))
				api.Get("/providers/gitlab/subgroups", uiapi.GitLabSubgroupsHandler(authService, providerStore, appCache))
				api.Get("/providers/gitlab/{group}/subgroups", uiapi.GitLabSubgroupsHandler(authService, providerStore, appCache))
				api.Get("/providers/gitlab/{projectPath}/details", uiapi.GitLabRepoDetailsHandler(authService, providerStore, appCache))
				api.Get("/providers/gitea/repos", uiapi.GiteaReposHandler(authService, providerStore, appCache, db))
				api.Get("/providers/gitea/{owner}/repos", uiapi.GiteaReposHandler(authService, providerStore, appCache, db))
				api.Get("/providers/gitea/orgs", uiapi.GiteaOrgsHandler(authService, providerStore, appCache))
				api.Get("/providers/gitea/{owner}/{repo}/details", uiapi.GiteaRepoDetailsHandler(authService, providerStore, appCache))

				// Runs endpoints
				api.Get("/runs", uiapi.RunsListHandler(db, authService))
				api.Post("/runs", uiapi.RunsCreateHandler(db, authService))
				api.Post("/scan-all", uiapi.ScanAllHandler(db, authService))
				api.Get("/runs/{id}", uiapi.RunGetHandler(db, authService))
				api.Get("/runs/{id}/stream", uiapi.RunStreamHandler(db, authService, func() *runner.K8sClient {
					if opts != nil {
						return opts.K8sClient
					}
					return nil
				}()))
				api.Get("/runs/{id}/secrets", uiapi.RunSecretsHandler(db, authService))

				// Kubernetes integration endpoints (only available if runner is enabled)
				if opts != nil && opts.K8sClient != nil {
					api.Get("/runs/{id}/k8s-logs", uiapi.RunLogsHandler(db, authService, opts.K8sClient))
					api.Get("/runs/{id}/k8s-status", uiapi.RunJobStatusHandler(db, authService, opts.K8sClient))
					api.Get("/runs/{id}/events", uiapi.RunEventsHandler(db, authService, opts.K8sClient))
				}
				if opts != nil && opts.RunExecutor != nil {
					api.Post("/runs/{id}/cancel", uiapi.RunCancelHandler(db, authService, opts.RunExecutor))
				}
			}
		})

		if spaHandler != nil && authService != nil {
			r.Handle("/*", authService.SPAGuard(spaHandler))
		}
	})

	return r
}
