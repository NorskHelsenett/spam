package server

import (
	"net/http"
	"time"

	"github.com/NorskHelsenett/spam/internal/acl"
	"github.com/NorskHelsenett/spam/internal/audit"
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
	// ACLProvider is the access-control grant source that handlers
	// reach via acl.ProviderFromRequest. Built once at startup so the
	// provider chain (LocalProvider today, later also OIDC-derived /
	// GitHub-App / external RBAC) stays out of handler signatures.
	ACLProvider acl.Provider
}

// NewRouter wires the HTTP routes and middleware for the API server.
func NewRouter(db *gorm.DB, authService *auth.Service, shutdown <-chan struct{}, opts *RouterOptions) http.Handler {
	r := chi.NewRouter()
	var providerStore *providerconfig.Store
	var appCache cache.Store
	var aclProvider acl.Provider
	if opts != nil {
		providerStore = opts.ProviderStore
		appCache = opts.Cache
		aclProvider = opts.ACLProvider
	}
	if appCache == nil {
		appCache = cache.NewMemory()
	}

	// Injects the configured ACL Provider into the request context
	// for every gated route. Handlers fetch it via
	// acl.ProviderFromRequest; a nil provider is treated as
	// fail-closed by the scope helpers, so the middleware is safe to
	// install even when the caller forgot to supply an ACLProvider.
	aclProviderInjector := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			next.ServeHTTP(w, r.WithContext(acl.WithProvider(r.Context(), aclProvider)))
		})
	}

	var syncMgr *uiapi.SyncManager
	if providerStore != nil {
		syncMgr = uiapi.NewSyncManager(db, providerStore, appCache)
	}

	// Resolves the current user id for audit records. Returns "" when no
	// session is loadable (the audit middleware only records successful
	// 2xx responses, so unauthenticated hits do not reach it).
	auditUserID := func(r *http.Request) string {
		if authService == nil {
			return ""
		}
		sess, err := authService.LoadSession(r)
		if err != nil || sess == nil {
			return ""
		}
		return sess.UserID
	}

	// ---------------------------------------------------------------
	// PUBLIC endpoints (no authentication).
	//
	// Only the following are intentionally reachable unauthenticated:
	//   - /api/healthz              liveness probe
	//   - /api/scam/callcenter      SCAM agent ingest
	//   - /api/scam/heartbeat       SCAM agent quiet-but-alive ping
	//   - /api/auth/login           OIDC entry
	//   - /api/auth/callback        OIDC return
	//   - /api/auth/me              UI probes current session state
	//   - /api/auth/logout          idempotent session clear
	//   - /api/auth/pending/stream  pre-approval polling (pending session)
	//
	// Everything else is gated by APIGuard below — fail-closed. New
	// endpoints added to the gated groups cannot accidentally leak
	// data because they never run without a valid session.
	// ---------------------------------------------------------------

	r.Get("/api/healthz", health.Handler(db))
	r.Post("/api/scam/callcenter", scam.CallcenterHandler(db, appCache))
	r.Post("/api/scam/heartbeat", scam.HeartbeatHandler(db))

	if authService != nil {
		r.Group(func(pub chi.Router) {
			pub.Use(middleware.RequestID)
			pub.Use(middleware.RealIP)
			pub.Use(middleware.Logger)
			pub.Use(middleware.Recoverer)
			pub.Use(middleware.Timeout(60 * time.Second))

			pub.Get("/api/auth/login", authService.LoginHandler())
			pub.Get("/api/auth/callback", authService.CallbackHandler())
			pub.Get("/api/auth/me", authService.MeHandler())
			pub.Post("/api/auth/logout", authService.LogoutHandler())
		})

		// Pending-approval SSE accepts a pending session (pre-approval),
		// not a full one, so it gets its own no-timeout group separate
		// from both the public and the authenticated SSE routes.
		r.Group(func(pend chi.Router) {
			pend.Use(middleware.RequestID)
			pend.Use(middleware.RealIP)
			pend.Use(middleware.Logger)
			pend.Use(middleware.Recoverer)
			pend.Use(cache.Middleware)
			pend.Get("/api/auth/pending/stream", events.PendingApprovalStream(authService.PendingSessionInfo, authService.UserApprovalStatus))
		})
	}

	// ---------------------------------------------------------------
	// GATED long-lived SSE endpoints — no Timeout middleware so the
	// server doesn't kill the connection mid-stream.
	// ---------------------------------------------------------------

	if authService != nil {
		r.Group(func(sse chi.Router) {
			sse.Use(middleware.RequestID)
			sse.Use(middleware.RealIP)
			sse.Use(middleware.Logger)
			sse.Use(middleware.Recoverer)
			sse.Use(cache.Middleware)
			sse.Use(authService.APIGuard)
			sse.Use(aclProviderInjector)

			sse.Get("/api/app/stream", events.AppStreamHandler(authService.SessionInfo, shutdown))
			sse.Get("/api/runs/active/stream", uiapi.RunsActiveStreamHandler(db, authService))
			sse.Get("/api/runs/{id}/stream", uiapi.RunStreamHandler(db, authService, func() *runner.K8sClient {
				if opts != nil {
					return opts.K8sClient
				}
				return nil
			}()))
			sse.Post("/api/scan-all", uiapi.ScanAllHandler(db, authService, providerStore))
		})
	}

	// ---------------------------------------------------------------
	// GATED JSON API endpoints.
	// ---------------------------------------------------------------

	if authService != nil {
		r.Group(func(priv chi.Router) {
			priv.Use(middleware.RequestID)
			priv.Use(middleware.RealIP)
			priv.Use(middleware.Logger)
			priv.Use(middleware.Recoverer)
			priv.Use(cache.Middleware)
			priv.Use(middleware.Timeout(60 * time.Second))
			priv.Use(authService.APIGuard)
			priv.Use(aclProviderInjector)

			priv.Route("/api", func(api chi.Router) {
				api.Get("/sboms/{id}", uiapi.SBOMGetHandler(db, authService))
				api.Get("/sboms/{id}/download", uiapi.SBOMDownloadHandler(db, authService))
				api.Get("/admin/users", uiapi.AdminUsersListHandler(db, authService))
				api.Patch("/admin/users/{userID}", uiapi.AdminUserRoleHandler(db, authService))
				api.Patch("/admin/users/{userID}/hidden", uiapi.AdminUserHiddenHandler(db, authService))
				// Provider routes return PAT fingerprints and rotate
				// secrets; every successful hit is audited so admin
				// reads/writes leave a trail.
				providerAudit := audit.Middleware(db, auditUserID, "admin.providers")
				api.With(providerAudit).Get("/admin/providers", uiapi.AdminProvidersListHandler(authService, providerStore))
				api.With(providerAudit).Post("/admin/providers", uiapi.AdminProvidersCreateHandler(authService, providerStore))
				api.With(providerAudit).Patch("/admin/providers/{id}", uiapi.AdminProvidersUpdateHandler(authService, providerStore))
				api.With(providerAudit).Post("/admin/providers/{id}/rotate", uiapi.AdminProvidersRotateHandler(authService, providerStore))
				api.With(providerAudit).Post("/admin/providers/{id}/sync", uiapi.AdminProvidersSyncHandler(authService, providerStore, syncMgr))
				api.Get("/admin/providers/sync/status", uiapi.AdminProvidersSyncStatusHandler(authService, providerStore, syncMgr))
				api.With(providerAudit).Delete("/admin/providers/{id}", uiapi.AdminProvidersDeleteHandler(authService, providerStore, appCache))
				api.Post("/admin/views/refresh", uiapi.AdminViewsRefreshHandler(db, authService))
				api.Get("/admin/views/status", uiapi.AdminViewsStatusHandler(db, authService))
				api.Post("/admin/cache/clear", uiapi.AdminCacheClearHandler(db, authService))
				api.Post("/admin/osv/scan", uiapi.AdminOSVScanHandler(db, authService))
				api.Get("/admin/osv/scan/status", uiapi.AdminOSVScanStatusHandler(db, authService))
				api.Post("/admin/sbom/scan", uiapi.AdminSBOMScanHandler(db, authService))
				api.Get("/admin/sbom/scan/status", uiapi.AdminSBOMScanStatusHandler(db, authService))
				api.Post("/admin/secrets/probe", uiapi.AdminSecretProbeScanHandler(db, authService))
				api.Get("/admin/secrets/probe/status", uiapi.AdminSecretProbeStatusHandler(db, authService))
				api.Get("/admin/secrets/probe/preview", uiapi.AdminSecretProbePreviewHandler(db, authService))
				api.Get("/admin/secrets/probe/list", uiapi.AdminSecretProbeListHandler(db, authService))
				api.Get("/admin/secrets/probe/export", uiapi.AdminSecretProbeExportHandler(db, authService))
				api.Post("/admin/secrets/probe/one", uiapi.AdminSecretProbeOneHandler(db, authService))
				api.Get("/admin/secrets/probe/audit", uiapi.AdminSecretProbeAuditHandler(db, authService))
				api.Get("/admin/secrets/probe/inspect", uiapi.AdminSecretProbeInspectHandler(db, authService))
				api.Post("/admin/secrets/probe/run", uiapi.AdminSecretProbeByHashHandler(db, authService))

				// Admin ACL grant management. Admin-only, audit-wrapped
				// so every grant add/remove leaves a trail.
				aclAudit := audit.Middleware(db, auditUserID, "admin.acl")
				api.With(aclAudit).Get("/admin/acl/grants", uiapi.AdminACLGrantsListHandler(db, authService))
				api.With(aclAudit).Post("/admin/acl/grants", uiapi.AdminACLGrantsCreateHandler(db, authService))
				api.With(aclAudit).Delete("/admin/acl/grants/{id}", uiapi.AdminACLGrantsDeleteHandler(db, authService))

				// Stats
				api.Get("/stats", uiapi.StatsHandler(db, authService))
				api.Get("/app/summary", uiapi.AppSummaryHandler(db, authService, appCache))

				// Ecosystems endpoint
				api.Get("/components/ecosystems", uiapi.EcosystemsListHandler(db, authService, appCache))

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

				// Cluster query endpoints — SCAM inventory (namespaces,
				// pods, images, hostnames, LB IPs). Gated via APIGuard
				// on the enclosing group.
				api.Get("/clusters/summary", scam.ClusterSummaryHandler(db))
				api.Get("/clusters/registry-distribution", scam.RegistryDistributionHandler(db))
				api.Get("/clusters/exposure", scam.ExposureHandler(db))
				api.Get("/clusters/images/detail", scam.ImageDetailHandler(db))
				api.Get("/clusters/chain", scam.ClusterChainHandler(db))
				api.Get("/clusters/hosts", scam.HostsHandler(db, appCache))
				api.Get("/clusters/hosts/chain", scam.HostChainHandler(db))
				api.Get("/clusters/hosts/resolve", scam.ResolveHostHandler(appCache))
				api.Get("/clusters/hosts/meta", scam.HostMetaHandler(appCache))
				api.Get("/clusters/hosts/favicon", scam.HostFaviconHandler(appCache))

				// Runs endpoints
				api.Get("/runs", uiapi.RunsListHandler(db, authService))
				api.Post("/runs", uiapi.RunsCreateHandler(db, authService))
				api.Post("/runs/failed/reschedule", uiapi.RunsRescheduleFailedHandler(db, authService))
				api.Delete("/runs/failed", uiapi.RunsDeleteFailedHandler(db, authService))
				// scan-all is registered in the no-timeout SSE group above
				api.Get("/runs/{id}", uiapi.RunGetHandler(db, authService))
				api.Post("/runs/{id}/retry", uiapi.RunRetryHandler(db, authService))
				// Run-secrets returns raw scan findings; gated admin-only
				// via AdminGuard, and every successful read is audited.
				api.With(
					authService.AdminGuard,
					audit.Middleware(db, auditUserID, "runs.secrets.read"),
				).Get("/runs/{id}/secrets", uiapi.RunSecretsHandler(db, authService))

				// Image-scan artifact download — per-artifact raw bytes.
				// The /runs/{id} endpoint already returns summaries as part
				// of the RunResponse for IMAGE_SCAN jobs.
				api.Get("/image-scans/{job_id}/artifacts/{artifact_id}/download",
					uiapi.ImageScanArtifactDownloadHandler(db, authService))

				// Image-as-first-class-entity routes: image profile page
				// and the reverse lookup from a repo to all images built
				// from it (matched via cached source_repo_id).
				api.Get("/images/{id}", uiapi.ImageDetailHandler(db, authService))
				api.Get("/repos/{repo_id}/images", uiapi.RepoImagesHandler(db, authService))
				api.Get("/repos/{repo_id}/workloads", uiapi.RepoWorkloadsHandler(db, authService))

				// Kubernetes integration endpoints (only available if runner is enabled)
				if opts != nil && opts.K8sClient != nil {
					api.Get("/runs/{id}/k8s-logs", uiapi.RunLogsHandler(db, authService, opts.K8sClient))
					api.Get("/runs/{id}/k8s-status", uiapi.RunJobStatusHandler(db, authService, opts.K8sClient))
					api.Get("/runs/{id}/events", uiapi.RunEventsHandler(db, authService, opts.K8sClient))
				}
				if opts != nil && opts.RunExecutor != nil {
					api.Post("/runs/{id}/cancel", uiapi.RunCancelHandler(db, authService, opts.RunExecutor))
				}
			})

			priv.Route("/api/vuln", func(v chi.Router) {
				v.Get("/summary", uiapi.VulnSummaryHandler(db, authService))
				v.Get("/repos", uiapi.VulnReposHandler(db, authService))
				v.Get("/trend", uiapi.VulnTrendHandler(db, authService))
				v.Get("/list", uiapi.VulnListHandler(db, authService))
				v.Get("/facets", uiapi.VulnFacetsHandler(db, authService))
			})
			// /api/vulnerabilities/{vuln_id} — full detail view.
			// Kept separate from /api/vuln/* because the plural form
			// matches the /app/vulnerabilities/{vuln_id} route and
			// resource-style paths, whereas /api/vuln/* is the list-
			// oriented dashboard namespace.
			priv.Get("/api/vulnerabilities/{vuln_id}", uiapi.VulnDetailHandler(db, authService))
			// /api/secrets is split into two trust bands. Aggregate
			// endpoints (counts + trends + per-asset tallies) carry
			// no credential text and so are safe for global_readers.
			// Raw findings + dismiss (which flips finding state) stay
			// admin-only. Every successful read is audited either way.
			priv.Route("/api/secrets", func(s chi.Router) {
				s.Use(audit.Middleware(db, auditUserID, "secrets.read"))

				// Aggregate / metadata — admin or global_reader.
				s.Group(func(meta chi.Router) {
					meta.Use(authService.AdminOrGlobalReaderGuard)
					meta.Get("/table", uiapi.SecretsDashboardTableHandler(db, authService, appCache))
					meta.Get("/stats", uiapi.SecretsDashboardStatsHandler(db, authService, appCache))
					meta.Get("/trend", uiapi.SecretsDashboardTrendHandler(db, authService, appCache))
					meta.Get("/images", uiapi.ImageSecretsTableHandler(db, authService))
				})

				// Raw credential text + state mutation — admin only.
				s.Group(func(raw chi.Router) {
					raw.Use(authService.AdminGuard)
					raw.Get("/findings", uiapi.SecretsFindingsHandler(db, authService))
					raw.Post("/dismiss", uiapi.SecretDismissHandler(db, authService, appCache))
				})
			})
		})
	}

	// SPA fallback — served as a separate top-level catch-all because
	// SPAGuard does its own per-request redirect logic (not an API guard).
	if spaHandler != nil && authService != nil {
		r.Group(func(sp chi.Router) {
			sp.Use(middleware.RequestID)
			sp.Use(middleware.RealIP)
			sp.Use(middleware.Logger)
			sp.Use(middleware.Recoverer)
			sp.Handle("/*", authService.SPAGuard(spaHandler))
		})
	}

	return r
}
