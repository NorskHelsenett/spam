package cache

import (
	"context"
	"net/http"
	"strings"
)

type cachePolicyKey struct{}

type RequestPolicy struct {
	Bypass bool
	Store  bool
}

// Middleware derives cache behavior from request headers.
// `Cache-Control: no-cache` and `max-age=0` bypass server-side cache reads.
// `Cache-Control: no-store` bypasses reads and suppresses cache writes.
func Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		policy := RequestPolicy{Store: true}

		cacheControl := strings.ToLower(r.Header.Get("Cache-Control"))
		pragma := strings.ToLower(r.Header.Get("Pragma"))

		if strings.Contains(cacheControl, "no-store") {
			policy.Bypass = true
			policy.Store = false
		} else if strings.Contains(cacheControl, "no-cache") ||
			strings.Contains(cacheControl, "max-age=0") ||
			strings.Contains(pragma, "no-cache") {
			policy.Bypass = true
		}

		ctx := context.WithValue(r.Context(), cachePolicyKey{}, policy)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func PolicyFromContext(ctx context.Context) RequestPolicy {
	policy, ok := ctx.Value(cachePolicyKey{}).(RequestPolicy)
	if !ok {
		return RequestPolicy{Store: true}
	}
	return policy
}

func ShouldBypass(ctx context.Context) bool {
	return PolicyFromContext(ctx).Bypass
}

func ShouldStore(ctx context.Context) bool {
	return PolicyFromContext(ctx).Store
}
