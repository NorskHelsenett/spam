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

	"github.com/NorskHelsenett/spam/internal/artifacts"
	"github.com/NorskHelsenett/spam/internal/assets"
	"github.com/NorskHelsenett/spam/internal/auth"
	"github.com/NorskHelsenett/spam/internal/config"
	"github.com/NorskHelsenett/spam/internal/db"
	"github.com/NorskHelsenett/spam/internal/events"
	"github.com/NorskHelsenett/spam/internal/jobs"
	"github.com/NorskHelsenett/spam/internal/manifests"
	"github.com/NorskHelsenett/spam/internal/providerconfig"
	"github.com/NorskHelsenett/spam/internal/runner"
	"github.com/NorskHelsenett/spam/internal/server"
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
		&runner.RunSecret{},
		&providerconfig.ProviderInstance{},
		&providerconfig.ProviderSecret{},
		&events.OutboxEvent{},
	); err != nil {
		return fmt.Errorf("migrate database: %w", err)
	}

	if err := providerconfig.EnsureDefaults(ctx, gormDB); err != nil {
		return fmt.Errorf("seed provider defaults: %w", err)
	}

	if err := db.EnsureViews(ctx, gormDB,
		"migrations/20260211_create_unique_active_create_run_jobs.sql",
		"migrations/20260206_drop_legacy_component_tables.sql",
		"migrations/20260204_create_materialized_view_refreshes.sql",
		"migrations/20260203_create_sbom_component_view.sql",
		"migrations/20260203_create_sbom_metadata_view.sql",
	); err != nil {
		return fmt.Errorf("bootstrap views: %w", err)
	}

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

	routerOpts.ProviderStore = providerconfig.NewStore(gormDB, cfg.ProviderSecretsKey)
	if warnings := routerOpts.ProviderStore.VerifyKey(ctx); len(warnings) > 0 {
		for _, w := range warnings {
			log.Printf("WARNING: provider secret key: %s", w)
		}
	}

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
