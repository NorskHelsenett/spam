package uiapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/NorskHelsenett/spam/internal/auth"
	"github.com/NorskHelsenett/spam/internal/llmadvisory"
	"gorm.io/gorm"
)

// AdminAISettingsListHandler returns the per-use-case LLM settings.
// GET /api/admin/ai/settings
func AdminAISettingsListHandler(db *gorm.DB, authService *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, err := authService.RequireAdmin(r); err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		rows, err := llmadvisory.ListSettings(r.Context(), db)
		if err != nil {
			http.Error(w, "failed to load settings", http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"settings": rows})
	}
}

// AdminAISettingsUpdateHandler updates one use case's settings.
// PUT /api/admin/ai/settings/{use_case}
func AdminAISettingsUpdateHandler(db *gorm.DB, authService *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, err := authService.RequireAdmin(r)
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		useCase := r.PathValue("use_case")
		if useCase != llmadvisory.UseCaseSummary && useCase != llmadvisory.UseCaseVerdict {
			http.Error(w, "unknown use case", http.StatusBadRequest)
			return
		}
		var body llmadvisory.Settings
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "invalid body", http.StatusBadRequest)
			return
		}
		body.UseCase = useCase
		body.UpdatedBy = user.Email
		if err := llmadvisory.SaveSettings(r.Context(), db, body); err != nil {
			http.Error(w, "failed to save settings", http.StatusInternalServerError)
			return
		}
		saved, err := llmadvisory.GetSettings(r.Context(), db, useCase)
		if err != nil {
			http.Error(w, "failed to reload settings", http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, saved)
	}
}

// AdminAITestHandler runs one use case against one real finding with
// the supplied (possibly unsaved) settings and returns the output
// plus the exact payload the model saw. Nothing is persisted — this
// is the prompt-tuning test bench.
// POST /api/admin/ai/test {use_case, asset_type, asset_id, settings{...}}
func AdminAITestHandler(db *gorm.DB, authService *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, err := authService.RequireAdmin(r); err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		var body struct {
			UseCase   string               `json:"use_case"`
			AssetType string               `json:"asset_type"`
			AssetID   string               `json:"asset_id"`
			Settings  llmadvisory.Settings `json:"settings"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "invalid body", http.StatusBadRequest)
			return
		}
		if body.UseCase != llmadvisory.UseCaseSummary && body.UseCase != llmadvisory.UseCaseVerdict {
			http.Error(w, "unknown use case", http.StatusBadRequest)
			return
		}
		if body.AssetType != "image" && body.AssetType != "repo" {
			http.Error(w, "asset_type must be image or repo", http.StatusBadRequest)
			return
		}

		sig, err := llmadvisory.LoadSignals(r.Context(), db, body.AssetType, body.AssetID)
		if err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				http.Error(w, "asset not found in asset_risk", http.StatusNotFound)
				return
			}
			http.Error(w, "failed to load asset", http.StatusInternalServerError)
			return
		}
		payload, err := llmadvisory.BuildPayload(r.Context(), db, sig)
		if err != nil {
			http.Error(w, "failed to build payload", http.StatusInternalServerError)
			return
		}

		cfg := body.Settings
		cfg.UseCase = body.UseCase

		start := time.Now()
		out, chatErr := llmadvisory.Chat(r.Context(), cfg, payload)
		resp := map[string]any{
			"payload":    json.RawMessage(payload),
			"latency_ms": time.Since(start).Milliseconds(),
		}
		if chatErr != nil {
			resp["error"] = chatErr.Error()
			writeJSON(w, http.StatusOK, resp)
			return
		}
		resp["output"] = out
		if body.UseCase == llmadvisory.UseCaseVerdict {
			if v, err := llmadvisory.ParseVerdict(out); err != nil {
				resp["verdict_parse_error"] = err.Error()
			} else {
				resp["verdict"] = v
			}
		}
		writeJSON(w, http.StatusOK, resp)
	}
}
