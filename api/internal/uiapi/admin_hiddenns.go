package uiapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/NorskHelsenett/spam/internal/auth"
	"github.com/NorskHelsenett/spam/internal/hiddenns"
	"gorm.io/gorm"
)

// AdminHiddenNamespacesListHandler returns the admin-curated namespace
// patterns hidden from regular users' cluster views.
// GET /api/admin/namespaces/hidden
func AdminHiddenNamespacesListHandler(db *gorm.DB, authService *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, err := authService.RequireAdmin(r); err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		rows, err := hiddenns.List(r.Context(), db)
		if err != nil {
			http.Error(w, "failed to load hidden namespaces", http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"items": rows})
	}
}

// AdminHiddenNamespacesCreateHandler adds a pattern (exact namespace
// name or glob like nhn-*).
// POST /api/admin/namespaces/hidden {pattern, note?}
func AdminHiddenNamespacesCreateHandler(db *gorm.DB, authService *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, err := authService.RequireAdmin(r)
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		var body struct {
			Pattern string `json:"pattern"`
			Note    string `json:"note"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "invalid body", http.StatusBadRequest)
			return
		}
		body.Pattern = strings.TrimSpace(body.Pattern)
		if err := hiddenns.ValidatePattern(body.Pattern); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if len(body.Note) > 512 {
			http.Error(w, "note exceeds 512 characters", http.StatusBadRequest)
			return
		}
		row, err := hiddenns.Create(r.Context(), db, body.Pattern, strings.TrimSpace(body.Note), user.Email)
		if err != nil {
			// The unique index on pattern is the only constraint that can
			// reject a validated insert.
			if errors.Is(err, gorm.ErrDuplicatedKey) || strings.Contains(err.Error(), "duplicate key") {
				http.Error(w, "pattern already exists", http.StatusConflict)
				return
			}
			http.Error(w, "failed to save pattern", http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusCreated, row)
	}
}

// AdminHiddenNamespacesDeleteHandler removes a pattern by id.
// DELETE /api/admin/namespaces/hidden/{id}
func AdminHiddenNamespacesDeleteHandler(db *gorm.DB, authService *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, err := authService.RequireAdmin(r); err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		id, err := strconv.ParseUint(r.PathValue("id"), 10, 64)
		if err != nil {
			http.Error(w, "invalid id", http.StatusBadRequest)
			return
		}
		if err := hiddenns.Delete(r.Context(), db, uint(id)); err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			http.Error(w, "failed to delete pattern", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}
