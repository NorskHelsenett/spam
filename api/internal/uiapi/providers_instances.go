package uiapi

import (
	"net/http"

	"github.com/NorskHelsenett/spam/internal/auth"
	"github.com/NorskHelsenett/spam/internal/providerconfig"
	"gorm.io/gorm"
)

func ProvidersInstancesHandler(db *gorm.DB, authService *auth.Service, store *providerconfig.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if authService != nil {
			if _, err := authService.LoadSession(r); err != nil {
				http.Error(w, "unauthenticated", http.StatusUnauthorized)
				return
			}
		}

		if store == nil {
			http.Error(w, "provider store unavailable", http.StatusInternalServerError)
			return
		}

		providers, err := store.ListPublic(r.Context())
		if err != nil {
			http.Error(w, "failed to load providers", http.StatusInternalServerError)
			return
		}

		writeJSON(w, http.StatusOK, providers)
	}
}
