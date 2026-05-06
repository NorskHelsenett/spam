package uiapi

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/NorskHelsenett/spam/internal/auth"
	"github.com/NorskHelsenett/spam/internal/signingpolicy"
	"gorm.io/gorm"
)

// Admin endpoints for the cosign verification policy. The image-
// scanner reads this row when running `cosign verify` against each
// image; a true verdict flips image_digests.verified_source to true,
// which is what the existing ACL inheritance already gates on (see
// acl/scope.go ReadableImageClause).
//
//   GET /api/admin/signing/cosign-policy   — current policy (key redacted)
//   PUT /api/admin/signing/cosign-policy   — upsert policy

// adminSigningPolicyResponse is the public shape returned to the
// admin UI. KeyPEM is never sent back — only KeyFingerprint, so the
// admin can confirm "yes that's the key I uploaded" without the
// material being readable from a browser cache.
type adminSigningPolicyResponse struct {
	Configured     bool                  `json:"configured"`
	PolicyType     signingpolicy.Type    `json:"policy_type,omitempty"`
	Enabled        bool                  `json:"enabled"`
	Issuer         string                `json:"issuer,omitempty"`
	SubjectPattern string                `json:"subject_pattern,omitempty"`
	KeyFingerprint string                `json:"key_fingerprint,omitempty"`
	UpdatedAt      string                `json:"updated_at,omitempty"`
}

// AdminSigningPolicyGetHandler returns the active cosign policy
// without the key material. Admin-only.
func AdminSigningPolicyGetHandler(db *gorm.DB, authService *auth.Service, secretsKey []byte) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if requireAdmin(w, r, authService) == nil {
			return
		}

		store := signingpolicy.NewStore(db, secretsKey)
		p, err := store.Get(r.Context())
		if errors.Is(err, signingpolicy.ErrNotFound) {
			writeJSON(w, http.StatusOK, adminSigningPolicyResponse{Configured: false})
			return
		}
		if err != nil {
			http.Error(w, "failed to load signing policy", http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, adminSigningPolicyResponse{
			Configured:     true,
			PolicyType:     p.Type,
			Enabled:        p.Enabled,
			Issuer:         p.Issuer,
			SubjectPattern: p.SubjectPattern,
			KeyFingerprint: p.KeyFingerprint,
			UpdatedAt:      p.UpdatedAt.UTC().Format("2006-01-02T15:04:05Z"),
		})
	}
}

// AdminSigningPolicyPutHandler upserts the policy. Body is the
// signingpolicy.UpsertInput; key_pem is encrypted before persist.
// Admin-only.
func AdminSigningPolicyPutHandler(db *gorm.DB, authService *auth.Service, secretsKey []byte) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := requireAdmin(w, r, authService)
		if user == nil {
			return
		}

		var in signingpolicy.UpsertInput
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			http.Error(w, "invalid JSON body", http.StatusBadRequest)
			return
		}

		store := signingpolicy.NewStore(db, secretsKey)
		updatedBy := user.ID
		if updatedBy == "" {
			updatedBy = "admin"
		}
		p, err := store.Upsert(r.Context(), in, updatedBy)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, http.StatusOK, adminSigningPolicyResponse{
			Configured:     true,
			PolicyType:     p.Type,
			Enabled:        p.Enabled,
			Issuer:         p.Issuer,
			SubjectPattern: p.SubjectPattern,
			KeyFingerprint: p.KeyFingerprint,
			UpdatedAt:      p.UpdatedAt.UTC().Format("2006-01-02T15:04:05Z"),
		})
	}
}

