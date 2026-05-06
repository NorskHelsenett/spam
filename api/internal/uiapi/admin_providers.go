package uiapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/NorskHelsenett/spam/internal/auth"
	"github.com/NorskHelsenett/spam/internal/cache"
	"github.com/NorskHelsenett/spam/internal/providerconfig"
)

type createProviderRequest struct {
	ProviderURL string `json:"provider_url"`
	DisplayName string `json:"display_name,omitempty"`
	Type        string `json:"type,omitempty"`
	PAT         string `json:"pat,omitempty"`
}

type updateProviderRequest struct {
	DisplayName   *string          `json:"display_name,omitempty"`
	Enabled       *bool            `json:"enabled,omitempty"`
	PollInterval  *int             `json:"poll_interval,omitempty"`
	DefaultGrants *json.RawMessage `json:"default_grants,omitempty"`
}

type rotateProviderRequest struct {
	PAT string `json:"pat"`
}

// adminProviderGuard validates admin auth and store availability.
// Returns the admin user on success, or writes an error response and returns nil.
func adminProviderGuard(w http.ResponseWriter, r *http.Request, authService *auth.Service, store *providerconfig.Store) *auth.User {
	if authService == nil {
		http.Error(w, "auth unavailable", http.StatusInternalServerError)
		return nil
	}

	adminUser, err := authService.RequireAdmin(r)
	if err != nil {
		http.Error(w, "forbidden", http.StatusForbidden)
		return nil
	}

	if store == nil {
		http.Error(w, "provider store unavailable", http.StatusInternalServerError)
		return nil
	}

	return adminUser
}

// requireProviderID extracts and validates the provider ID from path.
// Returns the ID on success, or writes an error response and returns empty string.
func requireProviderID(w http.ResponseWriter, r *http.Request) string {
	providerID := strings.TrimSpace(r.PathValue("id"))
	if providerID == "" {
		http.Error(w, "provider id required", http.StatusBadRequest)
		return ""
	}
	return providerID
}

func AdminProvidersListHandler(authService *auth.Service, store *providerconfig.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if adminProviderGuard(w, r, authService, store) == nil {
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

func AdminProvidersCreateHandler(authService *auth.Service, store *providerconfig.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		adminUser := adminProviderGuard(w, r, authService, store)
		if adminUser == nil {
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

		if msg, err := providerconfig.CheckProviderHealth(r.Context(), provider.Type, provider.BaseURL, provider.OwnerPath, strings.TrimSpace(req.PAT)); err != nil {
			if msg == "" {
				msg = "provider health check failed"
			}
			http.Error(w, msg, http.StatusBadRequest)
			return
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
		_ = store.UpdateHealth(r.Context(), created.ID, providerconfig.ProviderHealthHealthy, "")

		writeJSON(w, http.StatusCreated, created)
	}
}

// AdminProvidersSyncHandler starts a background sync and returns 202 immediately.
// Returns 409 if a sync is already running for that provider.
func AdminProvidersSyncHandler(authService *auth.Service, store *providerconfig.Store, mgr *SyncManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if adminProviderGuard(w, r, authService, store) == nil {
			return
		}

		providerID := requireProviderID(w, r)
		if providerID == "" {
			return
		}

		started, state := mgr.StartSync(providerID)
		if !started {
			writeJSON(w, http.StatusConflict, state)
			return
		}

		writeJSON(w, http.StatusAccepted, state)
	}
}

// AdminProvidersSyncStatusHandler returns the current sync state for all providers.
// Used on page load to restore sync state when navigating back to the settings page.
func AdminProvidersSyncStatusHandler(authService *auth.Service, store *providerconfig.Store, mgr *SyncManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if adminProviderGuard(w, r, authService, store) == nil {
			return
		}
		writeJSON(w, http.StatusOK, mgr.GetAllStatuses())
	}
}

func AdminProvidersUpdateHandler(authService *auth.Service, store *providerconfig.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if adminProviderGuard(w, r, authService, store) == nil {
			return
		}

		providerID := requireProviderID(w, r)
		if providerID == "" {
			return
		}

		var req updateProviderRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}

		// Update regular fields first when any are set; SetDefaultGrants
		// is a separate call because it rejects a zero-update payload,
		// and an admin can legitimately patch only default_grants.
		var updated *providerconfig.AdminProvider
		if req.DisplayName != nil || req.Enabled != nil || req.PollInterval != nil {
			u, err := store.Update(r.Context(), providerID, req.DisplayName, req.Enabled, req.PollInterval)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			updated = u
		}

		if req.DefaultGrants != nil {
			u, err := store.SetDefaultGrants(r.Context(), providerID, *req.DefaultGrants)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			updated = u
		}

		if updated == nil {
			http.Error(w, "no updates provided", http.StatusBadRequest)
			return
		}
		writeJSON(w, http.StatusOK, updated)
	}
}

func AdminProvidersRotateHandler(authService *auth.Service, store *providerconfig.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		adminUser := adminProviderGuard(w, r, authService, store)
		if adminUser == nil {
			return
		}

		providerID := requireProviderID(w, r)
		if providerID == "" {
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

func AdminProvidersDeleteHandler(authService *auth.Service, store *providerconfig.Store, c cache.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if adminProviderGuard(w, r, authService, store) == nil {
			return
		}

		providerID := requireProviderID(w, r)
		if providerID == "" {
			return
		}

		deletedRepoIDs, err := store.Delete(r.Context(), providerID)
		if err != nil {
			http.Error(w, "failed to delete provider", http.StatusInternalServerError)
			return
		}

		// Evict per-repo cache entries.
		for _, repoID := range deletedRepoIDs {
			_ = cache.Delete(r.Context(), c, fmt.Sprintf("contributors:%s", repoID))
		}
		// Evict aggregate caches that include provider data.
		_ = cache.Delete(r.Context(), c, appSummaryCacheKey)

		w.WriteHeader(http.StatusNoContent)
	}
}
