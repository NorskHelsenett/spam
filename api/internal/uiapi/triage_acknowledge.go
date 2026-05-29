package uiapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/NorskHelsenett/spam/internal/acl"
	"github.com/NorskHelsenett/spam/internal/assetrisk"
	"github.com/NorskHelsenett/spam/internal/audit"
	"github.com/NorskHelsenett/spam/internal/auth"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// acknowledgeRequest is the wire shape of POST /api/triage/acknowledge.
// SnoozeUntil is required when action="snooze" and ignored otherwise —
// validation happens inside assetrisk.CreateAck so the API surface
// stays a single doc.
type acknowledgeRequest struct {
	AssetType   string  `json:"asset_type"`
	AssetID     string  `json:"asset_id"`
	Action      string  `json:"action"`
	ReasonText  string  `json:"reason_text"`
	SnoozeUntil *string `json:"snooze_until,omitempty"` // RFC3339
}

// TriageAcknowledgeHandler creates a new bucket-level ack on an asset.
// Auth: any approved user who can read the asset (admin / global_reader
// via their wildcard grant, or default users whose ACL grants cover it).
// global_reader gets a 403 because their role is read-only; admin and
// default both pass when ACL allows.
//
// Side effects on success:
//   1. Any existing live ack on the same asset is revoked (manual).
//   2. A new ack row is inserted with the operator's email as
//      created_by and SignalsFingerprint snapshot for the asset.
//   3. assetrisk.TriggerRefresh is NOT called — the bucket recompute is
//      a pure runtime filter in LoadTriage now, so the next /api/triage
//      call already reflects the change.
func TriageAcknowledgeHandler(db *gorm.DB, authService *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireApproved(w, r) {
			return
		}
		subj := acl.SubjectFromRequest(r)
		if subj.IsGlobalReader && !subj.IsAdmin {
			http.Error(w, "global_reader is read-only", http.StatusForbidden)
			return
		}

		var req acknowledgeRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid body", http.StatusBadRequest)
			return
		}
		req.AssetType = strings.ToLower(strings.TrimSpace(req.AssetType))
		req.AssetID = strings.TrimSpace(req.AssetID)
		req.Action = strings.TrimSpace(req.Action)

		// Reuse the breakdown loader: it both ACL-checks and returns
		// the signals snapshot we need for the fingerprint. Hides
		// existence on no-grant with 404 — same as the breakdown.
		visible, signals, err := loadAssetSignals(r, db, req.AssetType, req.AssetID)
		if err != nil {
			http.Error(w, "failed to load asset", http.StatusInternalServerError)
			return
		}
		if !visible {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}

		session, err := authService.LoadSession(r)
		if err != nil || session == nil || session.Email == "" {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		actor := struct {
			ID    string
			Email string
		}{ID: session.UserID, Email: session.Email}

		ack := &assetrisk.Acknowledgment{
			AssetType:          req.AssetType,
			AssetID:            req.AssetID,
			Action:             req.Action,
			ReasonText:         strings.TrimSpace(req.ReasonText),
			SignalsFingerprint: assetrisk.SignalsFingerprint(signals),
			CreatedBy:          actor.Email,
		}
		if req.SnoozeUntil != nil && *req.SnoozeUntil != "" {
			t, err := time.Parse(time.RFC3339, *req.SnoozeUntil)
			if err != nil {
				http.Error(w, "invalid snooze_until (RFC3339)", http.StatusBadRequest)
				return
			}
			tt := t.UTC()
			ack.SnoozeUntil = &tt
		}

		// Append-only: revoke previous live ack so the partial index
		// 'one live row per (asset_type, asset_id)' isn't relied on
		// (we don't have it), and history clearly reflects supersession.
		err = db.WithContext(r.Context()).Transaction(func(tx *gorm.DB) error {
			if _, err := assetrisk.RevokeLiveAck(r.Context(), tx, req.AssetType, req.AssetID, actor.Email, assetrisk.AckRevokedManual); err != nil {
				return err
			}
			return assetrisk.CreateAck(r.Context(), tx, ack)
		})
		if err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			// Surface validation errors raised inside CreateAck so the
			// frontend can show the message without sniffing a generic
			// 500. Anything else is a real server problem.
			if isClientAckError(err) {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			http.Error(w, "failed to record acknowledgment", http.StatusInternalServerError)
			return
		}

		// Audit row: append-only "who muted what" for the security
		// team. The ack table already carries created_by/created_at,
		// but mirroring into audit_log keeps the cross-system query
		// ("all admin-write activity") on one table.
		audit.RecordRequest(db, r, actor.ID, "triage.acknowledge",
			req.AssetType+":"+req.AssetID, http.StatusCreated)

		writeJSON(w, http.StatusCreated, ack)
	}
}

// TriageRevokeAckHandler revokes a specific ack by its UUID. Used for
// the "unmute" flow where the operator clicks revoke on a history row
// or the live-ack banner.
func TriageRevokeAckHandler(db *gorm.DB, authService *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireApproved(w, r) {
			return
		}
		subj := acl.SubjectFromRequest(r)
		if subj.IsGlobalReader && !subj.IsAdmin {
			http.Error(w, "global_reader is read-only", http.StatusForbidden)
			return
		}

		idStr := chi.URLParam(r, "id")
		id, err := uuid.Parse(idStr)
		if err != nil {
			http.Error(w, "invalid id", http.StatusBadRequest)
			return
		}

		// Load the ack so we can ACL-check the underlying asset before
		// revoking — otherwise a user who lost cluster grants could
		// still revoke acks on those assets.
		var ack assetrisk.Acknowledgment
		if err := db.WithContext(r.Context()).First(&ack, "id = ?", id).Error; err != nil {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		visible, _, err := loadAssetSignals(r, db, ack.AssetType, ack.AssetID)
		if err != nil {
			http.Error(w, "failed to verify access", http.StatusInternalServerError)
			return
		}
		if !visible {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}

		session, err := authService.LoadSession(r)
		if err != nil || session == nil || session.Email == "" {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		actor := struct {
			ID    string
			Email string
		}{ID: session.UserID, Email: session.Email}

		if err := assetrisk.RevokeByID(r.Context(), db, id, actor.Email); err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				http.Error(w, "already revoked", http.StatusConflict)
				return
			}
			http.Error(w, "failed to revoke", http.StatusInternalServerError)
			return
		}

		audit.RecordRequest(db, r, actor.ID, "triage.acknowledge.revoke",
			ack.AssetType+":"+ack.AssetID+":"+id.String(), http.StatusNoContent)

		w.WriteHeader(http.StatusNoContent)
	}
}

// isClientAckError tells handler-side validation errors (raised inside
// CreateAck) apart from real server problems. We deliberately match on
// the exact strings CreateAck returns so a future refactor that
// surfaces different errors doesn't accidentally widen 4xx coverage.
func isClientAckError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	for _, prefix := range []string{
		"asset identity required",
		"created_by required",
		"snooze action requires",
		"invalid action",
	} {
		if strings.HasPrefix(msg, prefix) {
			return true
		}
	}
	return false
}
