// Package signingpolicy stores and retrieves the cosign verification
// policy used by the image-scanner. The runner threads the policy
// through ImageScanPayload so each scan can verify against the
// admin-configured identity (Sigstore keyless issuer/subject, or a
// pinned public key) and populate image_digests.verified_source
// honestly.
package signingpolicy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/NorskHelsenett/spam/internal/providerconfig"
	"gorm.io/gorm"
)

// PolicyName is the PK for the single global cosign policy. Schema
// is keyed by name so a follow-up can introduce per-scope-pattern
// policies (e.g. one for prod-cluster images) without a migration.
const PolicyName = "cosign"

// Type enumerates the supported cosign verification modes.
type Type string

const (
	// TypeKeyless verifies signatures against a Sigstore Fulcio cert
	// whose subject matches a regex and was issued by a specific OIDC
	// provider. Common case for GitHub Actions / Buildkite / Tekton.
	TypeKeyless Type = "keyless"

	// TypeKey verifies signatures against a pinned public key. Useful
	// when the org runs its own signing pipeline outside of Sigstore.
	TypeKey Type = "key"
)

// Policy is the GORM-mapped row of the signing_policy table.
type Policy struct {
	Name             string    `gorm:"primaryKey;column:name"`
	PolicyType       Type      `gorm:"column:policy_type"`
	Enabled          bool      `gorm:"column:enabled"`
	Issuer           string    `gorm:"column:issuer"`
	SubjectPattern   string    `gorm:"column:subject_pattern"`
	KeyPEMEncrypted  []byte    `gorm:"column:key_pem_encrypted"`
	KeyFingerprint   string    `gorm:"column:key_fingerprint"`
	CreatedAt        time.Time `gorm:"column:created_at"`
	UpdatedAt        time.Time `gorm:"column:updated_at"`
	UpdatedBy        string    `gorm:"column:updated_by"`
}

func (Policy) TableName() string { return "signing_policy" }

// Store wraps the DB + encryption key so callers don't pass them
// through everywhere.
type Store struct {
	db  *gorm.DB
	key []byte
}

func NewStore(db *gorm.DB, key []byte) *Store {
	return &Store{db: db, key: key}
}

// ErrNotFound means no policy row exists yet (fresh deploy or admin
// hasn't configured one). Callers should treat this as "verification
// disabled" — same posture as the old behaviour.
var ErrNotFound = errors.New("signing policy not configured")

// Get returns the active policy row decrypted, or ErrNotFound when no
// policy has been configured.
func (s *Store) Get(ctx context.Context) (*ResolvedPolicy, error) {
	var row Policy
	err := s.db.WithContext(ctx).First(&row, "name = ?", PolicyName).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	resolved := &ResolvedPolicy{
		Type:           row.PolicyType,
		Enabled:        row.Enabled,
		Issuer:         row.Issuer,
		SubjectPattern: row.SubjectPattern,
		KeyFingerprint: row.KeyFingerprint,
		UpdatedAt:      row.UpdatedAt,
	}
	if len(row.KeyPEMEncrypted) > 0 {
		pem, err := providerconfig.DecryptToken(s.key, row.KeyPEMEncrypted)
		if err != nil {
			return nil, err
		}
		resolved.KeyPEM = pem
	}
	return resolved, nil
}

// GetEnabled returns the policy only when it's configured AND
// enabled. The image-scanner uses this — if the policy exists but is
// disabled, scans go through the legacy "tree only" path so admins
// can pause verification without deleting their config.
func (s *Store) GetEnabled(ctx context.Context) (*ResolvedPolicy, error) {
	p, err := s.Get(ctx)
	if err != nil {
		return nil, err
	}
	if !p.Enabled {
		return nil, ErrNotFound
	}
	return p, nil
}

// ResolvedPolicy is the decrypted, runtime-shaped policy. KeyPEM is
// the plaintext public key when policy_type='key', empty otherwise.
type ResolvedPolicy struct {
	Type           Type      `json:"policy_type"`
	Enabled        bool      `json:"enabled"`
	Issuer         string    `json:"issuer,omitempty"`
	SubjectPattern string    `json:"subject_pattern,omitempty"`
	KeyPEM         string    `json:"key_pem,omitempty"`
	KeyFingerprint string    `json:"key_fingerprint,omitempty"`
	UpdatedAt      time.Time `json:"updated_at,omitempty"`
}

// Upsert validates and writes the policy. The key_pem (if provided)
// is encrypted at rest under the same PROVIDER_SECRETS_KEY used by
// provider_secrets — the env var is already required by every
// deployment, so this avoids forcing admins to manage a second key.
//
// updatedBy is the caller's user id, persisted for audit visibility
// in the admin UI.
func (s *Store) Upsert(ctx context.Context, in UpsertInput, updatedBy string) (*ResolvedPolicy, error) {
	if err := in.Validate(); err != nil {
		return nil, err
	}

	row := Policy{
		Name:           PolicyName,
		PolicyType:     in.Type,
		Enabled:        in.Enabled,
		Issuer:         strings.TrimSpace(in.Issuer),
		SubjectPattern: strings.TrimSpace(in.SubjectPattern),
		UpdatedAt:      time.Now().UTC(),
		UpdatedBy:      updatedBy,
	}

	keyPEM := strings.TrimSpace(in.KeyPEM)
	if keyPEM != "" {
		blob, err := providerconfig.EncryptToken(s.key, keyPEM)
		if err != nil {
			return nil, err
		}
		row.KeyPEMEncrypted = blob
		sum := sha256.Sum256([]byte(keyPEM))
		row.KeyFingerprint = "sha256:" + hex.EncodeToString(sum[:8])
	}

	// ON CONFLICT update preserves CreatedAt while bumping the rest.
	err := s.db.WithContext(ctx).Save(&row).Error
	if err != nil {
		return nil, err
	}
	return s.Get(ctx)
}

// UpsertInput is the wire-format admin payload — keys camel-cased
// the way the JSON decoder expects.
type UpsertInput struct {
	Type           Type   `json:"policy_type"`
	Enabled        bool   `json:"enabled"`
	Issuer         string `json:"issuer,omitempty"`
	SubjectPattern string `json:"subject_pattern,omitempty"`
	KeyPEM         string `json:"key_pem,omitempty"`
}

// Validate rejects payloads that can't be acted on. We don't compile
// the subject_pattern regex here — Go's regexp engine is the same one
// cosign uses, so admin gets a clear error from the runner if their
// pattern is malformed; rejecting at admin-PUT time would just
// duplicate that check without catching different bugs.
func (in UpsertInput) Validate() error {
	switch in.Type {
	case TypeKeyless:
		if strings.TrimSpace(in.Issuer) == "" {
			return errors.New("keyless policy requires issuer")
		}
		if strings.TrimSpace(in.SubjectPattern) == "" {
			return errors.New("keyless policy requires subject_pattern")
		}
	case TypeKey:
		if strings.TrimSpace(in.KeyPEM) == "" {
			return errors.New("key policy requires key_pem")
		}
	default:
		return errors.New("policy_type must be 'keyless' or 'key'")
	}
	return nil
}
