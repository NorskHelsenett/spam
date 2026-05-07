package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/NorskHelsenett/spam/internal/acl"
	"github.com/NorskHelsenett/spam/internal/artifacts"
	"github.com/NorskHelsenett/spam/internal/assets"
	"github.com/NorskHelsenett/spam/internal/assetrisk"
	"github.com/NorskHelsenett/spam/internal/dephealth"
	"github.com/NorskHelsenett/spam/internal/audit"
	"github.com/NorskHelsenett/spam/internal/auth"
	"github.com/NorskHelsenett/spam/internal/cache"
	"github.com/NorskHelsenett/spam/internal/config"
	"github.com/NorskHelsenett/spam/internal/db"
	"github.com/NorskHelsenett/spam/internal/events"
	"github.com/NorskHelsenett/spam/internal/imagescan"
	"github.com/NorskHelsenett/spam/internal/jobs"
	"github.com/NorskHelsenett/spam/internal/manifests"
	"github.com/NorskHelsenett/spam/internal/scam"
	"github.com/NorskHelsenett/spam/internal/secretprobe"
	"github.com/NorskHelsenett/spam/internal/providerconfig"
	"github.com/NorskHelsenett/spam/internal/runner"
	"github.com/NorskHelsenett/spam/internal/server"
	"github.com/NorskHelsenett/spam/internal/signingpolicy"
	"github.com/NorskHelsenett/spam/internal/uiapi"
	"github.com/NorskHelsenett/spam/internal/vulnerabilities"
	"github.com/NorskHelsenett/spam/internal/vulnmetrics"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	gormDB, err := db.Open(ctx, db.Config{DSN: cfg.DatabaseURL})
	if err != nil {
		return fmt.Errorf("connect database: %w", err)
	}
	defer func() {
		if closeErr := db.Close(gormDB); closeErr != nil {
			log.Printf("database close error: %v", closeErr)
		}
	}()

	if err := gormDB.AutoMigrate(
		&db.ViewSchemaVersion{},
		&auth.Session{},
		&auth.User{},
		&auth.Group{},
		&auth.UserGroup{},
		&assets.Repo{},
		&assets.RepoCommit{},
		&assets.ImageDigest{},
		&artifacts.SBOM{},
		&artifacts.SBOMBinding{},
		&manifests.Manifest{},
		&manifests.ManifestDependency{},
		&jobs.Job{},
		&runner.Run{},
		&runner.RunLog{},
		&runner.RunSecret{},
		// Image-scan tables are also migrated by the worker, but the API
		// server needs them too so local-dev seeding (image_scan_seed.sql)
		// doesn't blow up when the worker isn't running.
		&imagescan.ImageScanRun{},
		&imagescan.ImageScanArtifact{},
		&imagescan.ImageVulnFinding{},
		&providerconfig.ProviderInstance{},
		&providerconfig.ProviderSecret{},
		&signingpolicy.Policy{},
		&dephealth.Health{},
		&vulnerabilities.ComponentVulnerability{},
		&vulnerabilities.ComponentVEX{},
		&vulnerabilities.SBOMScanLease{},
		&vulnerabilities.SBOMScanResult{},
		&secretprobe.SecretProbe{},
		&secretprobe.ProbeAuditLog{},
		&secretprobe.SecretDismissal{},
		&scam.Record{},
		&scam.ClusterSession{},
		&scam.Cluster{},
		&audit.Log{},
		&acl.Grant{},
	); err != nil {
		return fmt.Errorf("migrate database: %w", err)
	}

	if err := db.EnsureViews(ctx, gormDB,
		"migrations/20260211_create_unique_active_create_run_jobs.sql",
		"migrations/20260223_create_unique_active_refresh_sbom_views_jobs.sql",
		"migrations/20260310_create_unique_active_osv_scan_job.sql",
		"migrations/20260206_drop_legacy_component_tables.sql",
		"migrations/20260204_create_materialized_view_refreshes.sql",
		"migrations/20260203_create_sbom_component_view.sql",
		"migrations/20260203_create_sbom_metadata_view.sql",
		"migrations/20260310_optimize_sbom_component_view_latest_per_repo.sql",
		"migrations/20260310_optimize_sbom_metadata_view_latest_per_repo.sql",
		"migrations/20260302_add_repo_search_trigram.sql",
		"migrations/20260303_add_repos_provider_instance_id.sql",
		"migrations/20260306_repos_identity_not_empty.sql",
		"migrations/20260311_fix_component_vulnerabilities_schema.sql",
		"migrations/20260310_create_trivy_scan_tables.sql",
		"migrations/20260312_enable_trivy_scan_history.sql",
		"migrations/20260312_create_vuln_dashboard_snapshots.sql",
		"migrations/20260310_fix_component_vulnerabilities_purl_column.sql",
		"migrations/20260311_create_view_unified_repositories_vulnerabilities.sql",
		"migrations/20260311_fix_sbom_component_view_implicit_root.sql",
		"migrations/20260317_add_repos_is_private.sql",
		"migrations/20260416_create_scam_indexes.sql",
		"migrations/20260420_dedupe_cluster_record_msg.sql",
		"migrations/20260421_rename_trivy_adhoc_job_type.sql",
		"migrations/20260422_create_acl_constraints.sql",
		"migrations/20260422_seed_acl_migration.sql",
		"migrations/20260422_rename_trivy_scan_to_sbom_scan.sql",
		"migrations/20260423_create_view_unified_image_vulnerabilities.sql",
		"migrations/20260423_create_vuln_metadata.sql",
		"migrations/20260423_add_vuln_metadata_canonical_id.sql",
		"migrations/20260429_create_cisa_kev_and_epss.sql",
		"migrations/20260429_create_unique_active_kev_epss_jobs.sql",
		"migrations/20260430_create_materialized_unified_vuln_views.sql",
		"migrations/20260506_create_asset_risk_view.sql",
		"migrations/20260507_create_signing_policy.sql",
		"migrations/20260507a_add_signing_policy_url_overrides.sql",
		"migrations/20260507c_unique_active_image_scan_job.sql",
		"migrations/20260508_create_dep_health.sql",
		"migrations/20260508a_unique_active_dep_health_job.sql",
		"migrations/20260508b_add_dep_health_versions_behind.sql",
	); err != nil {
		return fmt.Errorf("bootstrap views: %w", err)
	}

	populateCtx, populateCancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer populateCancel()
	if err := db.EnsureViewsPopulated(populateCtx, gormDB); err != nil {
		return fmt.Errorf("populate views: %w", err)
	}

	// Enqueue a refresh so the worker picks up any data accumulated since
	// the last refresh (e.g. across a server restart). The unique index on
	// active REFRESH_SBOM_VIEWS jobs means this is a no-op if one is already
	// queued; the error is intentionally ignored.
	if _, err := jobs.CreateJob(ctx, gormDB, jobs.CreateJobInput{
		Type: jobs.JobTypeRefreshSBOMViews,
	}); err != nil {
		log.Printf("startup view refresh job (may already be queued): %v", err)
	}

	// Populate the unified-vuln materialized views asynchronously. The
	// migration creates them WITH NO DATA so init is instant; this kicks
	// off the first build in the background so HTTP serving starts now
	// rather than after a multi-minute populate. TriggerRefresh debounces
	// so this coalesces with any concurrent scan-completion triggers.
	// Endpoints that read the MVs short-circuit to empty until the first
	// populate lands (see vulnmetrics.unifiedViewsReady).
	vulnmetrics.TriggerRefresh(gormDB)
	// asset_risk MV is similarly created WITH NO DATA — populate
	// async so /api/triage starts returning real data once the
	// underlying vuln MVs and cluster_record table are warm.
	assetrisk.TriggerRefresh(gormDB)

	seedSQLPath := strings.TrimSpace(os.Getenv("SPAM_SEED_SQL"))
	if seedSQLPath != "" {
		if err := db.RunSeedSQL(ctx, gormDB, seedSQLPath); err != nil {
			return fmt.Errorf("seed database: %w", err)
		}
	}

	events.StartNotificationListener(ctx, cfg.DatabaseURL)

	// Optionally create K8s client for runner endpoints (read-only)
	var routerOpts *server.RouterOptions
	if runnerCfg, err := config.LoadRunnerConfigOptional(); err == nil && runnerCfg.Enabled {
		k8sClient, err := runner.NewK8sClient(runnerCfg)
		if err != nil {
			log.Printf("warning: failed to create k8s client for API: %v (K8s endpoints will be unavailable)", err)
		} else {
			routerOpts = &server.RouterOptions{
				K8sClient: k8sClient,
			}
			log.Printf("K8s client enabled for API server")
		}
	}

	if routerOpts == nil {
		routerOpts = &server.RouterOptions{}
	}

	if err := cache.EnsureTable(ctx, gormDB); err != nil {
		return fmt.Errorf("ensure kv_store table: %w", err)
	}
	routerOpts.Cache = cache.NewPostgresStore(gormDB)
	routerOpts.HMACKey = strings.TrimSpace(os.Getenv("RUNNER_HMAC_KEY"))
	routerOpts.ProviderStore = providerconfig.NewStore(gormDB, cfg.ProviderSecretsKey)
	routerOpts.SecretsKey = cfg.ProviderSecretsKey
	// ACL chain: LocalProvider reads acl_grants. Future stages
	// (OIDC-claim-derived, GitHub App, external RBAC) append here.
	routerOpts.ACLProvider = &acl.ChainProvider{
		Providers: []acl.Provider{acl.NewLocalProvider(gormDB)},
	}
	if warnings := routerOpts.ProviderStore.VerifyKey(ctx); len(warnings) > 0 {
		for _, w := range warnings {
			log.Printf("WARNING: provider secret key: %s", w)
		}
	}

	uiapi.WarmCache(gormDB, routerOpts.ProviderStore, routerOpts.Cache)

	authService, err := auth.NewService(ctx, auth.Config{
		IssuerURL:         cfg.OIDC.IssuerURL,
		ClientID:          cfg.OIDC.ClientID,
		ClientSecret:      cfg.OIDC.ClientSecret,
		RedirectURL:       cfg.OIDC.RedirectURL,
		Scopes:            cfg.OIDC.Scopes,
		SessionCookieName: cfg.OIDC.SessionCookieName,
		AuthCookieName:    cfg.OIDC.AuthCookieName,
		SessionTTL:        cfg.OIDC.SessionTTL,
		CookieHashKey:     cfg.OIDC.CookieHashKey,
		CookieBlockKey:    cfg.OIDC.CookieBlockKey,
		CookieSecure:      cfg.OIDC.CookieSecure,
	}, gormDB)
	if err != nil {
		return fmt.Errorf("init oidc auth: %w", err)
	}

	shutdownCh := make(chan struct{})
	router := server.NewRouter(gormDB, authService, shutdownCh, routerOpts)

	addr := cfg.HTTPPort
	if !strings.HasPrefix(addr, ":") {
		addr = ":" + addr
	}

	srv := &http.Server{
		Addr:              addr,
		Handler:           router,
		ReadHeaderTimeout: 15 * time.Second,
	}

	go func() {
		<-ctx.Done()
		close(shutdownCh)

		shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()

		if err := srv.Shutdown(shutdownCtx); err != nil {
			log.Printf("server shutdown error: %v", err)
		}
	}()

	log.Printf("API listening on %s", addr)

	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("http server: %w", err)
	}

	return nil
}
