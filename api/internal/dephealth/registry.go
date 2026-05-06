package dephealth

import (
	"context"
	"sync"

	"gorm.io/gorm"
)

// RegisteredResolvers returns the active set of per-ecosystem
// resolvers. Centralising the registry in one function means the
// processor doesn't carry an init-time wiring step — config changes
// (e.g. disabling a flaky resolver via env var) take effect on the
// next sweep without a worker restart.
//
// Phase 3b ships npm + Go modules. Adding more (PyPI, RubyGems,
// crates.io, NuGet, Maven) is purely additive — drop a resolver
// file and append it here.
func RegisteredResolvers() []Resolver {
	return []Resolver{
		newNpmResolver(),
		newGoResolver(),
	}
}

// RegisteredProvider returns the source-repo provider fetcher used
// for activity metadata (last_pushed_at, archived flag, stars).
// Backed by a GitHub fetcher that reuses the first configured
// GitHub provider's PAT for rate-limit headroom; falls back to
// unauthenticated requests (60/h) when no provider is configured.
func RegisteredProvider(ctx context.Context, db *gorm.DB) ProviderFetcher {
	return loadGitHubFetcher(ctx, db)
}

// SetGitHubToken stashes a GitHub PAT for the lazily-constructed
// GitHub fetcher. Worker main.go calls this once at boot after
// resolving the most recent GitHub provider's secret. Empty token
// = unauthenticated requests (60 req/h, painful in production).
//
// Using a package-level variable rather than threading the token
// through every call keeps dephealth a leaf in the import graph —
// it deliberately doesn't import providerconfig (which transitively
// imports assets, creating a cycle through jobs).
func SetGitHubToken(token string) {
	tokenMu.Lock()
	currentToken = token
	tokenMu.Unlock()
}

var (
	tokenMu      sync.RWMutex
	currentToken string
)

func currentGitHubToken() string {
	tokenMu.RLock()
	defer tokenMu.RUnlock()
	return currentToken
}
