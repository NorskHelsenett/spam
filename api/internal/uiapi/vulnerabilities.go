package uiapi

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/NorskHelsenett/spam/internal/acl"
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
//
// SnoozeUntil/ReasonText/AssetScope are optional and were added
// 2026-05-28 alongside the triage-ack work. AssetScope narrows the
// suppression to one image ("image:<digest>") or one cluster
// ("cluster:<id>"); empty means global (legacy behaviour). SnoozeUntil
// is RFC3339; when set, the VEX expires automatically on the next
// asset_risk refresh after the timestamp.
type VEXSetRequest struct {
	PURL          string  `json:"purl"`
	VulnID        string  `json:"vuln_id"`
	Status        string  `json:"status"`        // affected | not_affected | fixed | under_investigation
	Justification string  `json:"justification"` // optional
	Detail        string  `json:"detail"`        // optional
	ReasonText    string  `json:"reason_text"`   // optional, free text
	AssetScope    string  `json:"asset_scope"`   // optional, "image:<digest>" | "cluster:<id>"
	SnoozeUntil   *string `json:"snooze_until"`  // optional, RFC3339
}

// DependencyVEXHandler upserts a VEX override for a PURL+vuln pair.
//
// POST /api/dependencies/vex
//
// Write authorisation: any approved user passes (we want default users
// to be able to suppress findings on assets they read). global_reader
// is blocked since their role is read-only. ACL on the asset itself is
// out of scope for v1 — VEX is per-(purl, vuln) and the underlying
// asset relationship is implicit. Tighten if abuse shows up.
func DependencyVEXHandler(db *gorm.DB, authService *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireApproved(w, r) {
			return
		}
		subj := acl.SubjectFromRequest(r)
		if subj.IsGlobalReader && !subj.IsAdmin {
			http.Error(w, "global_reader is read-only", http.StatusForbidden)
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

		scope := strings.TrimSpace(req.AssetScope)
		if scope != "" && !strings.HasPrefix(scope, "image:") && !strings.HasPrefix(scope, "cluster:") {
			http.Error(w, "asset_scope must be empty or prefixed with image: / cluster:", http.StatusBadRequest)
			return
		}

		input := vulnerabilities.VEXInput{
			ReasonText: strings.TrimSpace(req.ReasonText),
			AssetScope: scope,
		}
		if req.SnoozeUntil != nil && *req.SnoozeUntil != "" {
			t, err := time.Parse(time.RFC3339, *req.SnoozeUntil)
			if err != nil {
				http.Error(w, "invalid snooze_until (RFC3339)", http.StatusBadRequest)
				return
			}
			tt := t.UTC()
			input.SnoozeUntil = &tt
		}
		if session, _ := authService.LoadSession(r); session != nil {
			input.CreatedBy = session.Email
		}

		if err := vulnerabilities.SetVEX(r.Context(), db, req.PURL, req.VulnID, req.Status, req.Justification, req.Detail, input); err != nil {
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
