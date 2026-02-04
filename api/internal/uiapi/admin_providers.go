package uiapi

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/NorskHelsenett/spam/internal/auth"
	"github.com/NorskHelsenett/spam/internal/providerconfig"
	"gorm.io/gorm"
)

type createProviderRequest struct {
	ProviderURL string `json:"provider_url"`
	DisplayName string `json:"display_name,omitempty"`
	Type        string `json:"type,omitempty"`
	PAT         string `json:"pat,omitempty"`
}

type updateProviderRequest struct {
	DisplayName *string `json:"display_name,omitempty"`
	Enabled     *bool   `json:"enabled,omitempty"`
}

type rotateProviderRequest struct {
	PAT string `json:"pat"`
}

func AdminProvidersListHandler(db *gorm.DB, authService *auth.Service, store *providerconfig.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if authService == nil {
			http.Error(w, "auth unavailable", http.StatusInternalServerError)
			return
		}

		if _, err := authService.RequireAdmin(r); err != nil {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}

		if store == nil {
			http.Error(w, "provider store unavailable", http.StatusInternalServerError)
			return
		}

		providers, err := store.ListAdmin(r.Context())
		if err != nil {
			http.Error(w, "failed to load providers", http.StatusInternalServerError)
			return
		}

		writeJSON(w, http.StatusOK, providers)
	}
}

func AdminProvidersCreateHandler(db *gorm.DB, authService *auth.Service, store *providerconfig.Store) http.HandlerFunc {
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

		if store == nil {
			http.Error(w, "provider store unavailable", http.StatusInternalServerError)
			return
		}

		var req createProviderRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}

		providerType, baseURL, ownerPath, err := providerconfig.ParseProviderURL(req.ProviderURL, strings.TrimSpace(req.Type))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		displayName := strings.TrimSpace(req.DisplayName)
		if displayName == "" {
			displayName = baseURL
			if ownerPath != "" {
				displayName = strings.TrimRight(baseURL, "/") + "/" + ownerPath
			}
		}

		provider := providerconfig.ProviderInstance{
			Type:        providerType,
			BaseURL:     strings.TrimRight(baseURL, "/"),
			OwnerPath:   strings.Trim(ownerPath, "/"),
			DisplayName: displayName,
			Enabled:     true,
		}

		created, err := store.Create(r.Context(), provider, req.PAT, adminUser.ID)
		if err != nil {
			if strings.Contains(err.Error(), "provider already exists") {
				http.Error(w, "provider already exists", http.StatusConflict)
				return
			}
			if strings.Contains(err.Error(), "provider secrets key not configured") {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		writeJSON(w, http.StatusCreated, created)
	}
}

func AdminProvidersUpdateHandler(db *gorm.DB, authService *auth.Service, store *providerconfig.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if authService == nil {
			http.Error(w, "auth unavailable", http.StatusInternalServerError)
			return
		}

		if _, err := authService.RequireAdmin(r); err != nil {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}

		if store == nil {
			http.Error(w, "provider store unavailable", http.StatusInternalServerError)
			return
		}

		providerID := strings.TrimSpace(r.PathValue("id"))
		if providerID == "" {
			http.Error(w, "provider id required", http.StatusBadRequest)
			return
		}

		var req updateProviderRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}

		updated, err := store.Update(r.Context(), providerID, req.DisplayName, req.Enabled)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		writeJSON(w, http.StatusOK, updated)
	}
}

func AdminProvidersRotateHandler(db *gorm.DB, authService *auth.Service, store *providerconfig.Store) http.HandlerFunc {
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

		if store == nil {
			http.Error(w, "provider store unavailable", http.StatusInternalServerError)
			return
		}

		providerID := strings.TrimSpace(r.PathValue("id"))
		if providerID == "" {
			http.Error(w, "provider id required", http.StatusBadRequest)
			return
		}

		var req rotateProviderRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}

		updated, err := store.RotateToken(r.Context(), providerID, req.PAT, adminUser.ID)
		if err != nil {
			if strings.Contains(err.Error(), "provider secrets key not configured") {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		writeJSON(w, http.StatusOK, updated)
	}
}

func AdminProvidersDeleteHandler(db *gorm.DB, authService *auth.Service, store *providerconfig.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if authService == nil {
			http.Error(w, "auth unavailable", http.StatusInternalServerError)
			return
		}

		if _, err := authService.RequireAdmin(r); err != nil {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}

		if store == nil {
			http.Error(w, "provider store unavailable", http.StatusInternalServerError)
			return
		}

		providerID := strings.TrimSpace(r.PathValue("id"))
		if providerID == "" {
			http.Error(w, "provider id required", http.StatusBadRequest)
			return
		}

		if err := store.Delete(r.Context(), providerID); err != nil {
			http.Error(w, "failed to delete provider", http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusNoContent)
	}
}
