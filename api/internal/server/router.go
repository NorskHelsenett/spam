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
	"github.com/NorskHelsenett/spam/internal/scam"
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
	HMACKey       string
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

	var syncMgr *uiapi.SyncManager
	if providerStore != nil {
		syncMgr = uiapi.NewSyncManager(db, providerStore, appCache)
	}

	// Health check endpoint without middleware to avoid noise in logs
	r.Get("/api/healthz", health.Handler(db))

	// SCAM ingest — open endpoint, no auth. Agents POST records here.
	r.Post("/api/scam/callcenter", scam.CallcenterHandler(db))

	// SSE / long-lived streaming endpoints — registered without the 60 s timeout
	// so the server doesn't kill the connection mid-stream.
	r.Group(func(r chi.Router) {
		r.Use(middleware.RequestID)
		r.Use(middleware.RealIP)
		r.Use(middleware.Logger)
		r.Use(middleware.Recoverer)
		r.Use(cache.Middleware)

		if authService != nil {
			r.Get("/api/app/stream", events.AppStreamHandler(authService.SessionInfo, shutdown))
			r.Get("/api/auth/pending/stream", events.PendingApprovalStream(authService.PendingSessionInfo, authService.UserApprovalStatus))
			r.Get("/api/runs/active/stream", uiapi.RunsActiveStreamHandler(db, authService))
			r.Get("/api/runs/{id}/stream", uiapi.RunStreamHandler(db, authService, func() *runner.K8sClient {
				if opts != nil {
					return opts.K8sClient
				}
				return nil
			}()))
			r.Post("/api/scan-all", uiapi.ScanAllHandler(db, authService, providerStore))
		}
	})

	// Apply middleware to all other routes
	r.Group(func(r chi.Router) {
		r.Use(middleware.RequestID)
		r.Use(middleware.RealIP)
		r.Use(middleware.Logger)
		r.Use(middleware.Recoverer)
		r.Use(cache.Middleware)
		r.Use(middleware.Timeout(60 * time.Second))

		r.Route("/api", func(api chi.Router) {
			if authService != nil {
				api.Route("/auth", func(authRouter chi.Router) {
					authRouter.Get("/login", authService.LoginHandler())
					authRouter.Get("/callback", authService.CallbackHandler())
					authRouter.Get("/me", authService.MeHandler())
					authRouter.Post("/logout", authService.LogoutHandler())
				})
				api.Post("/sboms/upload", uiapi.SBOMUploadHandler(db, authService))
				api.Get("/sboms/{id}", uiapi.SBOMGetHandler(db, authService))
				api.Get("/sboms/{id}/download", uiapi.SBOMDownloadHandler(db, authService))
				api.Get("/admin/users", uiapi.AdminUsersListHandler(db, authService))
				api.Patch("/admin/users/{userID}", uiapi.AdminUserRoleHandler(db, authService))
				api.Patch("/admin/users/{userID}/hidden", uiapi.AdminUserHiddenHandler(db, authService))
				api.Get("/admin/providers", uiapi.AdminProvidersListHandler(authService, providerStore))
				api.Post("/admin/providers", uiapi.AdminProvidersCreateHandler(authService, providerStore))
				api.Patch("/admin/providers/{id}", uiapi.AdminProvidersUpdateHandler(authService, providerStore))
				api.Post("/admin/providers/{id}/rotate", uiapi.AdminProvidersRotateHandler(authService, providerStore))
				api.Post("/admin/providers/{id}/sync", uiapi.AdminProvidersSyncHandler(authService, providerStore, syncMgr))
				api.Get("/admin/providers/sync/status", uiapi.AdminProvidersSyncStatusHandler(authService, providerStore, syncMgr))
				api.Delete("/admin/providers/{id}", uiapi.AdminProvidersDeleteHandler(authService, providerStore, appCache))
				api.Post("/admin/views/refresh", uiapi.AdminViewsRefreshHandler(db, authService))
				api.Get("/admin/views/status", uiapi.AdminViewsStatusHandler(db, authService))
				api.Post("/admin/cache/clear", uiapi.AdminCacheClearHandler(db, authService))
				api.Post("/admin/osv/scan", uiapi.AdminOSVScanHandler(db, authService))
				api.Get("/admin/osv/scan/status", uiapi.AdminOSVScanStatusHandler(db, authService))
				api.Post("/admin/trivy/scan", uiapi.AdminTrivyScanHandler(db, authService))
				api.Get("/admin/trivy/scan/status", uiapi.AdminTrivyScanStatusHandler(db, authService))
				api.Post("/admin/secrets/probe", uiapi.AdminSecretProbeScanHandler(db, authService))
				api.Get("/admin/secrets/probe/status", uiapi.AdminSecretProbeStatusHandler(db, authService))
				api.Get("/admin/secrets/probe/preview", uiapi.AdminSecretProbePreviewHandler(db, authService))
				api.Get("/admin/secrets/probe/list", uiapi.AdminSecretProbeListHandler(db, authService))
				api.Get("/admin/secrets/probe/export", uiapi.AdminSecretProbeExportHandler(db, authService))
				api.Post("/admin/secrets/probe/one", uiapi.AdminSecretProbeOneHandler(db, authService))
				api.Get("/admin/secrets/probe/audit", uiapi.AdminSecretProbeAuditHandler(db, authService))
				api.Get("/admin/secrets/probe/inspect", uiapi.AdminSecretProbeInspectHandler(db, authService))
				api.Post("/admin/secrets/probe/run", uiapi.AdminSecretProbeByHashHandler(db, authService))

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
				api.Get("/dependencies/export/full.csv", uiapi.DependencyExportFullCSVHandler(db, authService))
				api.Get("/dependencies/export/detail.csv", uiapi.DependencyDetailExportCSVHandler(db, authService))
				api.Get("/dependencies/detail", uiapi.DependencyDetailHandler(db, authService))
				api.Get("/dependencies/assets", uiapi.DependencyAssetsHandler(db, authService))
				api.Get("/dependencies/vulnerabilities", uiapi.DependencyVulnerabilitiesHandler(db, authService))
				api.Post("/dependencies/vex", uiapi.DependencyVEXHandler(db, authService))
				api.Get("/search/advanced", uiapi.AdvancedSearchHandler(db, authService))
				api.Get("/search/preview", uiapi.AdvancedSearchPreviewHandler(db, authService))
				api.Get("/repos/search", uiapi.RepoSearchHandler(db, authService))
				api.Get("/repos/contributors", uiapi.RepoContributorsHandler(db, authService, providerStore, appCache))
				api.Get("/repos/dependencies/list", uiapi.RepoDependenciesListHandler(db, authService))
				api.Get("/repos/security", uiapi.RepoSecurityCountsHandler(db, authService))
				api.Get("/repos/secrets/list", uiapi.RepoSecretsListHandler(db, authService))
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

				// Cluster query endpoints (authenticated, data from SCAM agents)
				api.Get("/clusters/summary", scam.ClusterSummaryHandler(db))
				api.Get("/clusters/registry-distribution", scam.RegistryDistributionHandler(db))
				api.Get("/clusters/exposure", scam.ExposureHandler(db))
				api.Get("/clusters/images/detail", scam.ImageDetailHandler(db))
				api.Get("/clusters/hosts", scam.HostsHandler(db))

				// Runs endpoints
				api.Get("/runs", uiapi.RunsListHandler(db, authService))
				api.Post("/runs", uiapi.RunsCreateHandler(db, authService))
				api.Post("/runs/failed/reschedule", uiapi.RunsRescheduleFailedHandler(db, authService))
				api.Delete("/runs/failed", uiapi.RunsDeleteFailedHandler(db, authService))
				// scan-all is registered in the no-timeout SSE group above
				api.Get("/runs/{id}", uiapi.RunGetHandler(db, authService))
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

		if authService != nil {
			r.Route("/api/vuln", func(v chi.Router) {
				v.Get("/summary", uiapi.VulnSummaryHandler(db, authService))
				v.Get("/repos", uiapi.VulnReposHandler(db, authService))
				v.Get("/trend", uiapi.VulnTrendHandler(db, authService))
				v.Get("/list", uiapi.VulnListHandler(db, authService))
			})
			r.Route("/api/secrets", func(s chi.Router) {
				s.Get("/table", uiapi.SecretsDashboardTableHandler(db, authService, appCache))
				s.Get("/stats", uiapi.SecretsDashboardStatsHandler(db, authService, appCache))
				s.Get("/trend", uiapi.SecretsDashboardTrendHandler(db, authService, appCache))
				s.Get("/findings", uiapi.SecretsFindingsHandler(db, authService))
				s.Post("/dismiss", uiapi.SecretDismissHandler(db, authService, appCache))
			})
		}

		if spaHandler != nil && authService != nil {
			r.Handle("/*", authService.SPAGuard(spaHandler))
		}
	})

	return r
}
