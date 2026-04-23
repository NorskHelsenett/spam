package uiapi

import (
	"encoding/json"
	"net/http"

	"github.com/NorskHelsenett/spam/internal/auth"
	"github.com/NorskHelsenett/spam/internal/vulnerabilities"
	"github.com/NorskHelsenett/spam/internal/vulnmetrics"
	"gorm.io/gorm"
)

// DependencyVulnerabilitiesHandler looks up OSV vulnerabilities for a single versioned PURL.
//
// GET /api/dependencies/vulnerabilities?purl=pkg:npm/lodash@4.17.20
//
// Results are cached in component_vulnerabilities for 24 h; VEX overrides from
// component_vex are merged in automatically.
func DependencyVulnerabilitiesHandler(db *gorm.DB, authService *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if requireAuth(w, r, authService) == nil {
			return
		}

		purl := r.URL.Query().Get("purl")
		if purl == "" {
			http.Error(w, "purl query parameter is required", http.StatusBadRequest)
			return
		}

		results, err := vulnerabilities.LookupPURL(r.Context(), db, purl)
		if err != nil {
			http.Error(w, "vulnerability lookup failed: "+err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(results)
	}
}

// VEXSetRequest is the request body for POST /api/dependencies/vex.
type VEXSetRequest struct {
	PURL          string `json:"purl"`
	VulnID        string `json:"vuln_id"`
	Status        string `json:"status"`         // affected | not_affected | fixed | under_investigation
	Justification string `json:"justification"`  // optional
	Detail        string `json:"detail"`         // optional
}

// DependencyVEXHandler upserts a VEX override for a PURL+vuln pair.
//
// POST /api/dependencies/vex
func DependencyVEXHandler(db *gorm.DB, authService *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if requireAuth(w, r, authService) == nil {
			return
		}

		var req VEXSetRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}

		if req.PURL == "" || req.VulnID == "" || req.Status == "" {
			http.Error(w, "purl, vuln_id, and status are required", http.StatusBadRequest)
			return
		}

		validStatuses := map[string]bool{
			"affected": true, "not_affected": true,
			"fixed": true, "under_investigation": true,
		}
		if !validStatuses[req.Status] {
			http.Error(w, "status must be one of: affected, not_affected, fixed, under_investigation", http.StatusBadRequest)
			return
		}

		if err := vulnerabilities.SetVEX(r.Context(), db, req.PURL, req.VulnID, req.Status, req.Justification, req.Detail); err != nil {
			http.Error(w, "failed to set VEX: "+err.Error(), http.StatusInternalServerError)
			return
		}

		// VEX changes shift severity counts for the operator viewing
		// the list — warm the dashboard cache in the background so
		// the next page render reflects the suppression/override.
		vulnmetrics.TriggerRefresh(db)

		w.WriteHeader(http.StatusNoContent)
	}
}
