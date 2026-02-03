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
	"github.com/NorskHelsenett/spam/internal/inventory"
	"github.com/NorskHelsenett/spam/internal/jobs"
	"github.com/NorskHelsenett/spam/internal/manifests"
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
		&inventory.Component{},
		&inventory.ComponentVersion{},
		&inventory.SBOMComponent{},
		&inventory.ComponentDependency{},
		&manifests.Manifest{},
		&manifests.ManifestDependency{},
		&jobs.Job{},
		&runner.Run{},
		&events.OutboxEvent{},
	); err != nil {
		return fmt.Errorf("migrate database: %w", err)
	}

	seedSQLPath := strings.TrimSpace(os.Getenv("SPAM_SEED_SQL"))
	if seedSQLPath != "" {
		if err := db.RunSeedSQL(ctx, gormDB, seedSQLPath); err != nil {
			return fmt.Errorf("seed database: %w", err)
		}
		seedSBOMPath := strings.TrimSpace(os.Getenv("SPAM_SEED_SBOM"))
		if seedSBOMPath == "" {
			seedSBOMPath = "sbom.cdx.json"
		}
		if err := db.SeedSBOMComponentsFromFile(ctx, gormDB, seedSBOMPath, "cyclonedx-json"); err != nil {
			return fmt.Errorf("seed sbom components: %w", err)
		}
	}

	events.StartNotificationListener(ctx, cfg.DatabaseURL)

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
	router := server.NewRouter(gormDB, authService, shutdownCh, nil)

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
