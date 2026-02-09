package uiapi

import (
	"net/http"

	"github.com/NorskHelsenett/spam/internal/auth"
)

// requireAuth checks admin or global_reader role for read operations.
// Returns the user if authorized, nil otherwise (response already written).
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
