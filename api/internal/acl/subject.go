package acl

import (
	"context"
	"net/http"
)

// Subject is the authenticated principal for a request. It is built
// once per request by the middleware and stashed in the request
// context. Admins bypass all ACL checks; everything else is resolved
// through the configured Provider chain.
type Subject struct {
	UserID     string
	GroupSlugs []string
	IsAdmin    bool
}

type ctxKey int

const (
	subjectKey ctxKey = iota
	providerKey
)

// WithProvider returns a derived context carrying p, so handlers can
// call Provider methods through context without threading it through
// every function signature.
func WithProvider(ctx context.Context, p Provider) context.Context {
	return context.WithValue(ctx, providerKey, p)
}

// ProviderFromContext returns the Provider stashed by the request
// middleware, or nil if absent. Scope helpers treat a nil provider as
// "no grants" (deny-by-default for clusters, public-only for repos),
// which matches the fail-closed posture of the rest of this package.
func ProviderFromContext(ctx context.Context) Provider {
	if ctx == nil {
		return nil
	}
	p, _ := ctx.Value(providerKey).(Provider)
	return p
}

// ProviderFromRequest is a convenience wrapper for handlers.
func ProviderFromRequest(r *http.Request) Provider {
	if r == nil {
		return nil
	}
	return ProviderFromContext(r.Context())
}

// WithSubject returns a derived context carrying subj.
func WithSubject(ctx context.Context, subj Subject) context.Context {
	return context.WithValue(ctx, subjectKey, subj)
}

// SubjectFromContext returns the Subject stashed by the middleware, or
// a zero Subject if none is present. A zero Subject has IsAdmin=false
// and no groups, so callers naturally deny access if middleware was
// skipped.
func SubjectFromContext(ctx context.Context) Subject {
	if ctx == nil {
		return Subject{}
	}
	s, _ := ctx.Value(subjectKey).(Subject)
	return s
}

// SubjectFromRequest is a convenience wrapper for handlers.
func SubjectFromRequest(r *http.Request) Subject {
	if r == nil {
		return Subject{}
	}
	return SubjectFromContext(r.Context())
}
