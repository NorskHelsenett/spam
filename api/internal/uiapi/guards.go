package uiapi

import (
	"net/http"

	"github.com/NorskHelsenett/spam/internal/acl"
	"github.com/NorskHelsenett/spam/internal/auth"
)

// requireAuth checks admin or global_reader role for read operations.
// Returns the user if authorized, nil otherwise (response already written).
//
// Despite the generic name this is the strict gate — APIGuard at the
// router enforces the same role on the whole subrouter, so most
// handlers under priv.Route("/api", ...) inherit it. Routes that live
// in the approved group (triage, /api/vuln/*, /api/images/{id}) must
// use requireApproved instead — calling this helper from there
// double-enforces the role gate and 403s cluster-only users even
// though their data is ACL-scope-aware.
func requireAuth(w http.ResponseWriter, r *http.Request, authService *auth.Service) *auth.User {
	if authService == nil {
		http.Error(w, "auth unavailable", http.StatusInternalServerError)
		return nil
	}
	user, err := authService.RequireAdminOrGlobalReader(r)
	if err != nil {
		http.Error(w, "forbidden", http.StatusForbidden)
		return nil
	}
	return user
}

// requireApproved is the gate for handlers in the approved router
// group: any approved session passes, and the handler is responsible
// for ACL-scoping its own rows. Reads the Subject the ApprovedGuard
// middleware already stashed in context, so this is a cheap O(1)
// check with no DB hit.
//
// Returns false (and writes 403) when no subject is present — that
// only happens if a handler somehow bypassed the guard. Returning
// true means the caller has at least an approved session; per-row
// access is decided downstream via the acl.Readable* clauses.
func requireApproved(w http.ResponseWriter, r *http.Request) bool {
	subj := acl.SubjectFromRequest(r)
	if subj.UserID == "" {
		http.Error(w, "forbidden", http.StatusForbidden)
		return false
	}
	return true
}

// requireAdmin checks admin role for write operations.
// Returns the user if authorized, nil otherwise (response already written).
func requireAdmin(w http.ResponseWriter, r *http.Request, authService *auth.Service) *auth.User {
	if authService == nil {
		http.Error(w, "auth unavailable", http.StatusInternalServerError)
		return nil
	}
	user, err := authService.RequireAdmin(r)
	if err != nil {
		http.Error(w, "forbidden", http.StatusForbidden)
		return nil
	}
	return user
}
