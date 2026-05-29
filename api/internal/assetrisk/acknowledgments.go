package assetrisk

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// Ack action enum values. Stored as plain TEXT in the DB; the column
// has a CHECK constraint so a typo here fails at write time, not read.
const (
	AckActionSnooze        = "snooze"
	AckActionSuppress      = "suppress_until_change"
	AckActionAcceptRisk    = "accept_risk"
	AckRevokedInfraChange  = "infra_change"
	AckRevokedManual       = "manual"
	AckRevokedSnoozeExpiry = "snooze_expired"
)

// Acknowledgment is the GORM model for triage_acknowledgments. Append-
// only by convention: every action writes a new row, revokes set
// revoked_at on the prior live row, no UPDATE-overwrite.
type Acknowledgment struct {
	ID                  uuid.UUID  `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"id"`
	AssetType           string     `gorm:"not null" json:"asset_type"`
	AssetID             string     `gorm:"not null" json:"asset_id"`
	Action              string     `gorm:"not null" json:"action"`
	ReasonText          string     `gorm:"not null;default:''" json:"reason_text"`
	SnoozeUntil         *time.Time `json:"snooze_until,omitempty"`
	SignalsFingerprint  string     `json:"signals_fingerprint,omitempty"`
	CreatedBy           string     `gorm:"not null" json:"created_by"`
	CreatedAt           time.Time  `gorm:"not null;default:now()" json:"created_at"`
	RevokedAt           *time.Time `json:"revoked_at,omitempty"`
	RevokedBy           string     `json:"revoked_by,omitempty"`
	RevokedReason       string     `json:"revoked_reason,omitempty"`
}

func (Acknowledgment) TableName() string { return "triage_acknowledgments" }

// IsLive reports whether the ack still suppresses its asset right now.
// Mirrors the SQL filter used by the bucket recomputation: not revoked,
// and either no snooze or the snooze hasn't expired yet.
func (a Acknowledgment) IsLive(now time.Time) bool {
	if a.RevokedAt != nil {
		return false
	}
	if a.SnoozeUntil != nil && !a.SnoozeUntil.After(now) {
		return false
	}
	return true
}

// SignalsFingerprint produces a stable hash of the threat- and trust-
// driving fields of a Signals row. Captured at ack time and re-computed
// during the asset_risk refresh — any drift means the suppression's
// premise has changed and the ack is revoked with reason='infra_change'.
//
// The user picked "any signal change" for the drift policy, so the
// fingerprint covers every scored field. If we ever want to relax this
// (e.g. ignore dep-health bumps), narrow the fields here and bump the
// version prefix so existing acks self-invalidate.
func SignalsFingerprint(s Signals) string {
	// Version prefix so a deliberate algorithm change invalidates every
	// existing suppression instead of silently misclassifying drift.
	payload := fmt.Sprintf(
		"v1|%s|%s|%d|%d|%d|%.6f|%t|%d|%t|%.2f|%t|%d|%t|%.2f|%d|%d|%d|%d",
		s.AssetType, s.AssetID,
		s.CriticalCount, s.HighCount, s.KEVCount, s.EPSSMax,
		s.HasFixForCritical, s.ActiveSecretCount, s.InternetExposed,
		s.SignedCommitsPct, s.ImageSigned, s.ScanAgeDays, s.HasSBOM,
		s.WorstDepHealthScore, s.ArchivedDepCount, s.DeprecatedDepCount,
		s.MaxMajorBehind, s.MajorBehindDepCount,
	)
	sum := sha256.Sum256([]byte(payload))
	return hex.EncodeToString(sum[:])
}

// LiveAckForAssets fetches the newest live ack per (asset_type, asset_id)
// for the given set. Used by both LoadTriage (to filter rows out) and
// the breakdown endpoint (to show "currently suppressed by …" badges).
//
// Single round-trip, server-side dedup via DISTINCT ON. The partial
// index idx_triage_ack_asset_active keeps the scan tight.
func LiveAckForAssets(ctx context.Context, db *gorm.DB, keys []AssetKey) (map[AssetKey]Acknowledgment, error) {
	if len(keys) == 0 {
		return nil, nil
	}
	types := make([]string, 0, len(keys))
	ids := make([]string, 0, len(keys))
	for _, k := range keys {
		types = append(types, k.Type)
		ids = append(ids, k.ID)
	}

	var rows []Acknowledgment
	err := db.WithContext(ctx).Raw(`
		SELECT DISTINCT ON (asset_type, asset_id)
		       id, asset_type, asset_id, action, reason_text, snooze_until,
		       signals_fingerprint, created_by, created_at,
		       revoked_at, revoked_by, revoked_reason
		FROM triage_acknowledgments
		WHERE revoked_at IS NULL
		  AND (snooze_until IS NULL OR snooze_until > NOW())
		  AND (asset_type, asset_id) IN (SELECT * FROM UNNEST(?::text[], ?::text[]))
		ORDER BY asset_type, asset_id, created_at DESC
	`, types, ids).Scan(&rows).Error
	if err != nil {
		return nil, err
	}
	out := make(map[AssetKey]Acknowledgment, len(rows))
	for _, r := range rows {
		out[AssetKey{Type: r.AssetType, ID: r.AssetID}] = r
	}
	return out, nil
}

// AssetKey is the composite identity of a triage row, used as a map key
// when joining asset signals back to their live ack.
type AssetKey struct {
	Type string
	ID   string
}

// HistoryForAsset returns every ack ever recorded on this asset, newest
// first. Powers the "previously acknowledged" panel in the modal so the
// operator sees who suppressed it before and why.
func HistoryForAsset(ctx context.Context, db *gorm.DB, assetType, assetID string) ([]Acknowledgment, error) {
	var rows []Acknowledgment
	err := db.WithContext(ctx).
		Where("asset_type = ? AND asset_id = ?", assetType, assetID).
		Order("created_at DESC").
		Limit(50).
		Find(&rows).Error
	return rows, err
}

// CreateAck inserts a new ack row. The caller is responsible for
// revoking any prior live ack first (in the same transaction) — a fresh
// ack does not auto-revoke the previous one because operations like
// "extend the snooze" mean we want history preserved cleanly.
func CreateAck(ctx context.Context, db *gorm.DB, ack *Acknowledgment) error {
	if ack.AssetType == "" || ack.AssetID == "" {
		return errors.New("asset identity required")
	}
	if ack.CreatedBy == "" {
		return errors.New("created_by required")
	}
	switch ack.Action {
	case AckActionSnooze:
		if ack.SnoozeUntil == nil {
			return errors.New("snooze action requires snooze_until")
		}
	case AckActionSuppress, AckActionAcceptRisk:
		// no extra fields required
	default:
		return fmt.Errorf("invalid action %q", ack.Action)
	}
	return db.WithContext(ctx).Create(ack).Error
}

// RevokeLiveAck marks any live ack for the asset as revoked. Returns
// the number of rows changed so the caller knows whether there was an
// in-effect suppression to clear.
func RevokeLiveAck(ctx context.Context, db *gorm.DB, assetType, assetID, by, reason string) (int64, error) {
	now := time.Now().UTC()
	res := db.WithContext(ctx).
		Model(&Acknowledgment{}).
		Where("asset_type = ? AND asset_id = ? AND revoked_at IS NULL", assetType, assetID).
		Updates(map[string]any{
			"revoked_at":     now,
			"revoked_by":     by,
			"revoked_reason": reason,
		})
	return res.RowsAffected, res.Error
}

// RevokeByID revokes a specific ack row. Used for the explicit "unmute"
// flow where the operator clicks revoke on a history row.
func RevokeByID(ctx context.Context, db *gorm.DB, id uuid.UUID, by string) error {
	now := time.Now().UTC()
	res := db.WithContext(ctx).
		Model(&Acknowledgment{}).
		Where("id = ? AND revoked_at IS NULL", id).
		Updates(map[string]any{
			"revoked_at":     now,
			"revoked_by":     by,
			"revoked_reason": AckRevokedManual,
		})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return gorm.ErrRecordNotFound
	}
	return nil
}

// RevokeOnDrift walks every live suppress_until_change ack, recomputes
// the fingerprint against the current signals, and revokes those that
// no longer match. Called from the asset_risk MV refresh hook so the
// invalidation runs without a separate cron.
//
// Multi-replica safe: a missed row is just suppressed for another tick;
// double-revocation is idempotent because the UPDATE filter requires
// revoked_at IS NULL.
func RevokeOnDrift(ctx context.Context, db *gorm.DB, current []Signals) (int, error) {
	if len(current) == 0 {
		return 0, nil
	}
	keys := make([]AssetKey, 0, len(current))
	currentByKey := make(map[AssetKey]string, len(current))
	for _, s := range current {
		k := AssetKey{Type: s.AssetType, ID: s.AssetID}
		keys = append(keys, k)
		currentByKey[k] = SignalsFingerprint(s)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].Type != keys[j].Type {
			return keys[i].Type < keys[j].Type
		}
		return keys[i].ID < keys[j].ID
	})

	live, err := LiveAckForAssets(ctx, db, keys)
	if err != nil {
		return 0, err
	}
	revoked := 0
	for k, ack := range live {
		if ack.Action != AckActionSuppress {
			continue
		}
		want, ok := currentByKey[k]
		if !ok {
			continue
		}
		if ack.SignalsFingerprint == want {
			continue
		}
		// Drift detected — revoke this specific row.
		if err := RevokeByID(ctx, db, ack.ID, "system"); err == nil {
			// Update reason from "manual" to "infra_change" — easier
			// to do as a follow-up UPDATE than thread reason through
			// RevokeByID, since manual-revoke is the common path.
			db.WithContext(ctx).
				Model(&Acknowledgment{}).
				Where("id = ?", ack.ID).
				Update("revoked_reason", AckRevokedInfraChange)
			revoked++
		}
	}
	return revoked, nil
}
