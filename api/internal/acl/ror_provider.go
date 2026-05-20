package acl

import (
	"context"
	"log"
	"time"

	"github.com/NorskHelsenett/spam/internal/cache"
	"github.com/NorskHelsenett/spam/internal/ror"
)

// RORProvider derives cluster-scope grants from the NHN ROR ACL API.
// It implements Provider and slots into ChainProvider next to
// LocalProvider — no handler change is required, because every scope
// helper already resolves grants through the chain.
//
// The provider only contributes for ScopeCluster. Other scope types
// pass through (return nil) so LocalProvider remains the source of
// truth for repo/image grants until those are migrated.
//
// Auth: the user's OIDC access token is pulled off the request
// context (acl.WithAccessToken / acl.AccessTokenFromContext) — see
// auth.Service.APIGuard, which stashes the session-decrypted,
// auto-refreshed token there. If no token is present we degrade to
// "no grants from ROR" rather than failing the request, so missing
// middleware or anonymous endpoints don't 500.
//
// Caching: full LookupResponse is cached in the shared cache.Store
// keyed by user id with a short TTL (RORProviderTTL). The cache is
// Postgres-backed in production, so multi-replica deployments stay
// coherent — one pod populates, the rest read the same row. Failure
// (404, 401, network) caches a sentinel "no grants" for the same TTL
// to avoid retry-storming a misbehaving ROR.
type RORProvider struct {
	Client *ror.Client
	Cache  cache.Store
	TTL    time.Duration
}

// RORProviderTTL is the default freshness window for cached lookups.
// Short enough that an ACL revocation propagates within minutes;
// long enough that a logged-in user hits ROR ~30 times/hour, not
// thousands.
const RORProviderTTL = 2 * time.Minute

// NewRORProvider builds a provider with sensible defaults. A nil
// client or cache disables the provider (Grants returns nil quickly).
func NewRORProvider(client *ror.Client, c cache.Store) *RORProvider {
	return &RORProvider{Client: client, Cache: c, TTL: RORProviderTTL}
}

// Grants returns the cluster patterns ROR says the subject can read.
// Rules:
//   - `scopes.ror.subject.globalscope.read == true`  → single wildcard
//     pattern (matches every cluster).
//   - otherwise, one `{ClusterID: <id>}` pattern per cluster whose
//     `scopes.cluster.subject.<id>.read == true`.
//
// Scope types other than ScopeCluster return nil so the chain keeps
// using LocalProvider for those.
func (p *RORProvider) Grants(ctx context.Context, subj Subject, scopeType string) ([]ScopePattern, error) {
	if p == nil || p.Client == nil || scopeType != ScopeCluster {
		return nil, nil
	}
	token := AccessTokenFromContext(ctx)
	if token == "" || subj.UserID == "" {
		return nil, nil
	}

	lookup := p.fetch(ctx, subj.UserID, token)
	if lookup == nil {
		return nil, nil
	}
	return patternsFromLookup(lookup), nil
}

// fetch reads the cached lookup or calls ROR. A nil return means "no
// grants" (either ROR said so or the call failed) — callers must
// treat that as deny rather than fall through.
func (p *RORProvider) fetch(ctx context.Context, userID, token string) *ror.LookupResponse {
	key := rorCacheKey(userID)
	if p.Cache != nil {
		if hit, ok, err := cache.GetJSON[ror.LookupResponse](ctx, p.Cache, key); err == nil && ok {
			return &hit
		}
	}
	lookup, err := p.Client.LookupACL(ctx, token, "", "")
	if err != nil {
		log.Printf("ror lookup for user %s: %v", userID, err)
		// Cache an empty response so transient failures don't turn
		// into a retry-storm. RORProviderTTL is short enough that
		// the next round trip happens within minutes anyway.
		if p.Cache != nil {
			_ = cache.SetJSON[ror.LookupResponse](ctx, p.Cache, key, ror.LookupResponse{}, p.TTL)
		}
		return nil
	}
	if p.Cache != nil {
		_ = cache.SetJSON[ror.LookupResponse](ctx, p.Cache, key, *lookup, p.TTL)
	}
	return lookup
}

func rorCacheKey(userID string) string {
	return "acl:ror:lookup:" + userID
}

// patternsFromLookup translates a ROR LookupResponse into the
// ScopePattern shape ChainProvider expects. Pulled out so tests can
// pin the projection without spinning up an HTTP client.
func patternsFromLookup(lookup *ror.LookupResponse) []ScopePattern {
	if lookup == nil || lookup.Scopes == nil {
		return nil
	}

	// Global read grant short-circuits — a single wildcard pattern
	// dominates the chain (compileClusterPatterns returns allMatch=true
	// when any wildcard pattern is present).
	if rorScope, ok := lookup.Scopes["ror"]; ok {
		if global, ok := rorScope.Subject[ror.GlobalScopeSubject]; ok && global.Read {
			return []ScopePattern{{}}
		}
	}

	clusterScope, ok := lookup.Scopes["cluster"]
	if !ok || len(clusterScope.Subject) == 0 {
		return nil
	}
	out := make([]ScopePattern, 0, len(clusterScope.Subject))
	for clusterID, access := range clusterScope.Subject {
		if !access.Read {
			continue
		}
		out = append(out, ScopePattern{ClusterID: clusterID})
	}
	return out
}
