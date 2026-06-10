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
	"github.com/NorskHelsenett/spam/internal/ror"
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
	// SecretsKey is the AES-GCM key used to en/decrypt provider PATs
	// and the cosign signing policy's optional pinned key material.
	SecretsKey []byte
	// RORClient is the optional NHN ROR API client. When nil, the
	// admin /ror/probe endpoint returns 503; when set, it powers the
	// admin probe and (later) the RORProvider in the ACL chain.
	RORClient *ror.Client
}

// NewRouter wires the HTTP routes and middleware for the API server.
func NewRouter(db *gorm.DB, authService *auth.Service, shutdown <-chan struct{}, opts *RouterOptions) http.Handler {
	r := chi.NewRouter()
	var providerStore *providerconfig.Store
	var appCache cache.Store
	var aclProvider acl.Provider
	var secretsKey []byte
	var rorClient *ror.Client
	if opts != nil {
		providerStore = opts.ProviderStore
		appCache = opts.Cache
		aclProvider = opts.ACLProvider
		secretsKey = opts.SecretsKey
		rorClient = opts.RORClient
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
			pub.Get("/api/auth/me", authService.MeHandler(aclProvider))
			pub.Post("/api/auth/logout", authService.LogoutHandler())

			// Per-user ROR cluster access — gated by an approved
			// session only (handler self-checks via LoadSession), not
			// APIGuard. Returns the clusters the caller can see in ROR
			// based on their EntraID identity + the service ApiKey.
			pub.Get("/api/me/clusters", uiapi.MeClustersHandler(authService, rorClient))
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

				// Admin jobs view — read-only, no audit wrap (it's a poll
				// target). Returns the queue grouped by worker pool so an
				// operator can see what's running across the three pools at
				// a glance.
				api.Get("/admin/jobs", uiapi.AdminJobsHandler(db, authService))

				// Admin database storage view — read-only, no audit wrap.
				// Surfaces pg_catalog/pg_stat_user_tables so an operator can
				// see per-table sizes, row counts, and bloat signals when
				// chasing performance issues.
				api.Get("/admin/db/storage", uiapi.AdminDBStorageHandler(db, authService))

				// Admin database maintenance — enqueues ANALYZE / VACUUM
				// ANALYZE jobs per table. VACUUM FULL / REINDEX are
				// deliberately not exposed (they take AccessExclusiveLock).
				// /recent returns the last 50 maintenance jobs so the UI
				// can show per-row state.
				api.Post("/admin/db/maintenance", uiapi.AdminDBMaintenanceHandler(db, authService))
				api.Post("/admin/db/maintenance/all", uiapi.AdminDBMaintenanceAllHandler(db, authService))
				api.Get("/admin/db/maintenance/recent", uiapi.AdminDBMaintenanceRecentHandler(db, authService))

				// DB activity / diagnostics — pg_stat_database aggregates,
				// pg_stat_activity live queries, pg_stat_statements top-N
				// (degrades cleanly if the extension isn't installed).
				api.Get("/admin/db/activity", uiapi.AdminDBActivityHandler(db, authService))
				api.Get("/admin/db/live-queries", uiapi.AdminDBLiveQueriesHandler(db, authService))
				api.Get("/admin/db/slow-queries", uiapi.AdminDBSlowQueriesHandler(db, authService))

				// Bulk vuln-feed refresh (CISA KEV, FIRST.org EPSS).
				// Manual trigger jumps the auto-schedule queue; status is
				// poll-friendly for the admin UI's progress bar.
				api.Post("/admin/feeds/{feed}/refresh", uiapi.AdminFeedRefreshHandler(db, authService))
				api.Get("/admin/feeds/status", uiapi.AdminFeedsStatusHandler(db, authService))

				// Cosign signing policy — admin manages the verifier
				// identity used by the image scanner. The image-scanner
				// reads the same row directly via the worker DB, so the
				// admin endpoint only needs GET (redacted) + PUT.
				api.Get("/admin/signing/cosign-policy", uiapi.AdminSigningPolicyGetHandler(db, authService, secretsKey))
				api.Put("/admin/signing/cosign-policy", uiapi.AdminSigningPolicyPutHandler(db, authService, secretsKey))

				// Stats
				api.Get("/stats", uiapi.StatsHandler(db, authService))
				api.Get("/app/summary", uiapi.AppSummaryHandler(db, authService, appCache))

				// Triage is now registered in the approved group below —
				// the handler scopes repo/image/cluster rows independently
				// via ReadableRepoClause / ReadableImageClause /
				// readableClusterIDSet, so cluster-only ROR users land on
				// a non-empty triage instead of bouncing off APIGuard's
				// admin/global_reader gate.

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

				// Cluster query endpoints used to live here, but were
				// promoted to the approved-only group below so regular
				// users (no admin/global_reader role) can view the
				// clusters their ROR ACL grants them access to. The
				// handlers already filter rows via clusterACLFilterCol,
				// so moving out of APIGuard is safe.

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

				// /api/images/{id} moved to the approved group below so
				// cluster-only users can open the image profile for a
				// container running in one of their clusters. The
				// handler now uses canReadImageByID, which honors the
				// cluster-image inheritance branch in
				// acl.ReadableImageClause.
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

			// /api/vuln/* endpoints (and /api/vulnerabilities/{id}) are
			// registered under the approved group below. Each handler
			// ACL-scopes its own rows. /api/vuln/trend is the one
			// exception data-shape-wise — it's a fleet-global daily
			// severity roll-up with no per-asset breakdown — but it
			// still goes through the approved group so cluster
			// operators see the same chart admins do. No identifying
			// info leaves the snapshot table.
			// /api/secrets is split into two trust bands. Aggregate
			// endpoints (counts + trends + per-asset tallies) carry
			// no credential text and so are safe for global_readers.
			// Raw findings + dismiss (which flips finding state) stay
			// admin-only. Every successful read is audited either way.
			priv.Route("/api/secrets", func(s chi.Router) {
				s.Use(audit.Middleware(db, auditUserID, "secrets.read"))

				// Repo-side aggregate / metadata — admin or global_reader.
				// /images is not here: cluster-only users need it too,
				// so it's registered in the approved group below.
				s.Group(func(meta chi.Router) {
					meta.Use(authService.AdminOrGlobalReaderGuard)
					meta.Get("/table", uiapi.SecretsDashboardTableHandler(db, authService, appCache))
					meta.Get("/stats", uiapi.SecretsDashboardStatsHandler(db, authService, appCache))
					meta.Get("/trend", uiapi.SecretsDashboardTrendHandler(db, authService, appCache))
				})

				// Raw credential text + state mutation — admin only.
				s.Group(func(raw chi.Router) {
					raw.Use(authService.AdminGuard)
					raw.Get("/findings", uiapi.SecretsFindingsHandler(db, authService))
					raw.Post("/dismiss", uiapi.SecretDismissHandler(db, authService, appCache))
				})
			})
		})

		// Approved-user group — endpoints whose data is fully ACL-filtered
		// per handler so regular users (no admin/global_reader role) can
		// see only the rows their grants allow. RORProvider drives the
		// cluster visibility here; LocalProvider stays the source of truth
		// for repo/image grants until those are migrated.
		r.Group(func(approved chi.Router) {
			approved.Use(middleware.RequestID)
			approved.Use(middleware.RealIP)
			approved.Use(middleware.Logger)
			approved.Use(middleware.Recoverer)
			approved.Use(cache.Middleware)
			approved.Use(middleware.Timeout(60 * time.Second))
			approved.Use(authService.ApprovedGuard)
			approved.Use(aclProviderInjector)

			// Image-grain secrets dashboard — readable by anyone whose
			// ACL grants resolve to images (admin, global_reader, or
			// cluster-only users via cluster_image_inventory). Repo-
			// side secrets (/api/secrets/table|stats|trend) stay in
			// the AdminOrGlobalReader band above.
			approved.Get("/api/secrets/images", uiapi.ImageSecretsTableHandler(db, authService))

			// Dashboard + vulnerability surfaces that scope rows per
			// subject through ReadableRepoClause / ReadableImageClause
			// (which now OR-s in cluster_image_inventory). Each handler
			// is responsible for its own filtering — APIGuard's role
			// gate is intentionally not in this group, so adding a
			// new endpoint here without ACL filtering would leak data.
			approved.Get("/api/triage", uiapi.TriageHandler(db, authService))
			approved.Get("/api/images/{id}", uiapi.ImageDetailHandler(db, authService))
			approved.Get("/api/images/{id}/vulnerabilities", uiapi.ImageVulnerabilitiesHandler(db, authService))
			approved.Get("/api/vuln/summary", uiapi.VulnSummaryHandler(db, authService))
			approved.Get("/api/vuln/list", uiapi.VulnListHandler(db, authService))
			approved.Get("/api/vuln/facets", uiapi.VulnFacetsHandler(db, authService))
			approved.Get("/api/vuln/repos", uiapi.VulnReposHandler(db, authService))
			approved.Get("/api/vuln/trend", uiapi.VulnTrendHandler(db, authService))
			approved.Get("/api/vulnerabilities/{vuln_id}", uiapi.VulnDetailHandler(db, authService))

			// Single-cluster detail surface — the cluster-scope analogue of
			// /api/images/{id}. {id} accepts the cluster_id, ROR slug, ROR
			// name, or display name; the handler resolves and ACL-gates it.
			approved.Get("/api/cluster/{id}", scam.ClusterDetailHandler(db))
			// Cluster-scoped advisory list — lazy companion to the detail
			// surface, grouped by canonical CVE over the cluster's images.
			approved.Get("/api/cluster/{id}/vulnerabilities", scam.ClusterVulnerabilitiesHandler(db))

			approved.Get("/api/clusters/summary", scam.ClusterSummaryHandler(db))
			approved.Get("/api/clusters/registry-distribution", scam.RegistryDistributionHandler(db))
			approved.Get("/api/clusters/exposure", scam.ExposureHandler(db))
			approved.Get("/api/clusters/images/detail", scam.ImageDetailHandler(db))
			approved.Get("/api/clusters/images/facets", scam.ImageFacetsHandler(db))
			approved.Get("/api/clusters/chain", scam.ClusterChainHandler(db))
			approved.Get("/api/clusters/hosts", scam.HostsHandler(db, appCache))
			approved.Get("/api/clusters/hosts/summary", scam.HostSummaryHandler(db, appCache))
			approved.Get("/api/clusters/hosts/chain", scam.HostChainHandler(db))
			approved.Get("/api/clusters/hosts/resolve", scam.ResolveHostHandler(appCache))
			approved.Get("/api/clusters/hosts/meta", scam.HostMetaHandler(appCache))
			approved.Get("/api/clusters/hosts/favicon", scam.HostFaviconHandler(appCache))
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
