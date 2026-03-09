package uiapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/NorskHelsenett/spam/internal/auth"
	"gorm.io/gorm"
)

type updateUserRoleRequest struct {
	Role string `json:"role"`
}

type updateUserHiddenRequest struct {
	Hidden bool `json:"hidden"`
}

func AdminUsersListHandler(db *gorm.DB, authService *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if authService == nil {
			http.Error(w, "auth unavailable", http.StatusInternalServerError)
			return
		}

		if _, err := authService.RequireAdmin(r); err != nil {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}

		users, err := authService.ListUsers(r.Context())
		if err != nil {
			http.Error(w, "failed to load users", http.StatusInternalServerError)
			return
		}

		writeJSON(w, http.StatusOK, users)
	}
}

func AdminUserRoleHandler(db *gorm.DB, authService *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if authService == nil {
			http.Error(w, "auth unavailable", http.StatusInternalServerError)
			return
		}

		adminUser, err := authService.RequireAdmin(r)
		if err != nil {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}

		userID := strings.TrimSpace(r.PathValue("userID"))
		if userID == "" {
			http.Error(w, "user id required", http.StatusBadRequest)
			return
		}

		var req updateUserRoleRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}

		result, err := authService.UpdateUserRole(r.Context(), userID, req.Role, adminUser.ID)
		if err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				http.Error(w, "user not found", http.StatusNotFound)
				return
			}
			http.Error(w, "failed to update user role", http.StatusBadRequest)
			return
		}

		writeJSON(w, http.StatusOK, result)
	}
}

func AdminUserHiddenHandler(db *gorm.DB, authService *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if authService == nil {
			http.Error(w, "auth unavailable", http.StatusInternalServerError)
			return
		}

		if _, err := authService.RequireAdmin(r); err != nil {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}

		userID := strings.TrimSpace(r.PathValue("userID"))
		if userID == "" {
			http.Error(w, "user id required", http.StatusBadRequest)
			return
		}

		var req updateUserHiddenRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}

		result, err := authService.SetUserHidden(r.Context(), userID, req.Hidden)
		if err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				http.Error(w, "user not found", http.StatusNotFound)
				return
			}
			http.Error(w, "failed to update user", http.StatusInternalServerError)
			return
		}

		writeJSON(w, http.StatusOK, result)
	}
}
