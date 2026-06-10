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
	"time"

	"gorm.io/gorm"
)

const (
	UseCaseSummary = "advisory_summary"
	UseCaseVerdict = "triage_verdict"
)

// Settings is one llm_settings row — sampling + prompt config for a
// single use case.
type Settings struct {
	UseCase      string    `json:"use_case"      gorm:"column:use_case;primaryKey"`
	Enabled      bool      `json:"enabled"       gorm:"column:enabled"`
	BaseURL      string    `json:"base_url"      gorm:"column:base_url"`
	APIKey       string    `json:"api_key"       gorm:"column:api_key"`
	Model        string    `json:"model"         gorm:"column:model"`
	SystemPrompt string    `json:"system_prompt" gorm:"column:system_prompt"`
	Temperature  float32   `json:"temperature"   gorm:"column:temperature"`
	TopK         int       `json:"top_k"         gorm:"column:top_k"`
	TopP         float32   `json:"top_p"         gorm:"column:top_p"`
	MaxTokens    int       `json:"max_tokens"    gorm:"column:max_tokens"`
	UpdatedAt    time.Time `json:"updated_at"    gorm:"column:updated_at"`
	UpdatedBy    string    `json:"updated_by"    gorm:"column:updated_by"`
}

func (Settings) TableName() string { return "llm_settings" }

func ListSettings(ctx context.Context, db *gorm.DB) ([]Settings, error) {
	var out []Settings
	err := db.WithContext(ctx).Order("use_case").Find(&out).Error
	return out, err
}

func GetSettings(ctx context.Context, db *gorm.DB, useCase string) (Settings, error) {
	var s Settings
	err := db.WithContext(ctx).Where("use_case = ?", useCase).First(&s).Error
	return s, err
}

// SaveSettings updates the tunable fields of one use case row.
func SaveSettings(ctx context.Context, db *gorm.DB, s Settings) error {
	return db.WithContext(ctx).Model(&Settings{}).
		Where("use_case = ?", s.UseCase).
		Updates(map[string]any{
			"enabled":       s.Enabled,
			"base_url":      s.BaseURL,
			"api_key":       s.APIKey,
			"model":         s.Model,
			"system_prompt": s.SystemPrompt,
			"temperature":   s.Temperature,
			"top_k":         s.TopK,
			"top_p":         s.TopP,
			"max_tokens":    s.MaxTokens,
			"updated_at":    time.Now(),
			"updated_by":    s.UpdatedBy,
		}).Error
}
