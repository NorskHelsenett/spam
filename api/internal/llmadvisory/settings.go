// Package llmadvisory generates natural-language advisories and
// shadow-mode triage verdicts for asset_risk findings via an
// OpenAI-compatible chat endpoint (Open WebUI / vLLM).
//
// Everything is admin-tunable per use case through the llm_settings
// table; output is cached in asset_advisories keyed by the asset's
// signals hash so the LLM only re-runs when the vuln story changes.
//
// The triage_verdict use case is SHADOW MODE by design: the verdict,
// justification, and confidence are recorded and displayed, but
// nothing is suppressed or closed. The future action path is
// authoring VEX records for human review — deliberately not built
// until the verdict quality has been observed in the wild.
package llmadvisory

import (
	"context"
	"errors"
	"time"

	"github.com/NorskHelsenett/spam/internal/secrets"
	"gorm.io/gorm"
)

const (
	UseCaseSummary = "advisory_summary"
	UseCaseVerdict = "triage_verdict"
)

// Settings is one llm_settings row — sampling + prompt config for a
// single use case.
//
// The API key follows the git-PAT custody model: encrypted at rest
// with the provider secrets key, plaintext never serialized to the
// admin UI (only the stored fingerprint travels). APIKey is a
// transient field — request input on save, decrypted value for
// internal callers via GetSettings.
type Settings struct {
	UseCase   string `json:"use_case"  gorm:"column:use_case;primaryKey"`
	Enabled   bool   `json:"enabled"   gorm:"column:enabled"`
	BaseURL   string `json:"base_url"  gorm:"column:base_url"`
	APIKeyEnc []byte `json:"-"         gorm:"column:api_key_enc"`
	APIKeyFP  string `json:"api_key_fingerprint,omitempty" gorm:"column:api_key_fp"`
	// APIKey is never persisted as-is: on PUT a non-empty value
	// replaces the stored key; GetSettings fills it with the
	// decrypted key for the chat client. Excluded from list output
	// by ListSettings clearing it (belt) + omitempty (suspenders).
	APIKey string `json:"api_key,omitempty" gorm:"-"`
	// ClearAPIKey removes the stored key on save.
	ClearAPIKey bool   `json:"clear_api_key,omitempty" gorm:"-"`
	Model       string `json:"model"     gorm:"column:model"`
	SystemPrompt string    `json:"system_prompt" gorm:"column:system_prompt"`
	Temperature  float32   `json:"temperature"   gorm:"column:temperature"`
	TopK         int       `json:"top_k"         gorm:"column:top_k"`
	TopP         float32   `json:"top_p"         gorm:"column:top_p"`
	MaxTokens    int       `json:"max_tokens"    gorm:"column:max_tokens"`
	UpdatedAt    time.Time `json:"updated_at"    gorm:"column:updated_at"`
	UpdatedBy    string    `json:"updated_by"    gorm:"column:updated_by"`
}

func (Settings) TableName() string { return "llm_settings" }

// secretsKey holds the AES key used for api_key_enc — the same
// provider secrets key that protects git PATs. Set once at startup
// from cmd/server and cmd/worker; nil means "no key configured", in
// which case saving an API key fails loudly and decryption is
// skipped.
var secretsKey []byte

// SetSecretsKey installs the AES key. Call before StartWorker / any
// settings access that touches API keys.
func SetSecretsKey(key []byte) { secretsKey = key }

// ListSettings returns all rows for the admin UI — API keys reduced
// to their stored fingerprint, plaintext never populated.
func ListSettings(ctx context.Context, db *gorm.DB) ([]Settings, error) {
	var out []Settings
	if err := db.WithContext(ctx).Order("use_case").Find(&out).Error; err != nil {
		return nil, err
	}
	for i := range out {
		out[i].APIKey = ""
		out[i].APIKeyEnc = nil
	}
	return out, nil
}

// GetSettings returns one use case with the API key decrypted for
// internal callers (chat client, worker). A missing/invalid secrets
// key degrades to an empty APIKey rather than failing the whole
// pipeline — the endpoint may legitimately need no auth.
func GetSettings(ctx context.Context, db *gorm.DB, useCase string) (Settings, error) {
	var s Settings
	if err := db.WithContext(ctx).Where("use_case = ?", useCase).First(&s).Error; err != nil {
		return s, err
	}
	if len(s.APIKeyEnc) > 0 && len(secretsKey) > 0 {
		if plain, err := secrets.DecryptToken(secretsKey, s.APIKeyEnc); err == nil {
			s.APIKey = plain
		}
	}
	return s, nil
}

// SaveSettings updates the tunable fields of one use case row. The
// API key columns only change when the caller supplies a new key
// (encrypted before write) or asks for a clear — an empty APIKey on
// an ordinary save leaves the stored key untouched.
func SaveSettings(ctx context.Context, db *gorm.DB, s Settings) error {
	updates := map[string]any{
		"enabled":       s.Enabled,
		"base_url":      s.BaseURL,
		"model":         s.Model,
		"system_prompt": s.SystemPrompt,
		"temperature":   s.Temperature,
		"top_k":         s.TopK,
		"top_p":         s.TopP,
		"max_tokens":    s.MaxTokens,
		"updated_at":    time.Now(),
		"updated_by":    s.UpdatedBy,
	}
	switch {
	case s.ClearAPIKey:
		updates["api_key_enc"] = []byte{}
		updates["api_key_fp"] = ""
	case s.APIKey != "":
		if len(secretsKey) == 0 {
			return errors.New("cannot store API key: provider secrets key is not configured")
		}
		enc, err := secrets.EncryptToken(secretsKey, s.APIKey)
		if err != nil {
			return err
		}
		updates["api_key_enc"] = enc
		updates["api_key_fp"] = secrets.FingerprintToken(s.APIKey)
	}
	return db.WithContext(ctx).Model(&Settings{}).
		Where("use_case = ?", s.UseCase).
		Updates(updates).Error
}
