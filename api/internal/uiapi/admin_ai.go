package uiapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/NorskHelsenett/spam/internal/auth"
	"github.com/NorskHelsenett/spam/internal/jobs"
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
		// The admin UI never holds the stored key's plaintext, so an
		// empty api_key in a test request means "use the saved one".
		if cfg.APIKey == "" {
			if stored, err := llmadvisory.GetSettings(r.Context(), db, body.UseCase); err == nil {
				cfg.APIKey = stored.APIKey
			}
		}

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

// AdminAIBackfillHandler enqueues an ADVISORY_BACKFILL job: generate
// advisories for every fix_now asset whose cache is missing or stale,
// without the background worker's batch cap.
// POST /api/admin/ai/backfill
func AdminAIBackfillHandler(db *gorm.DB, authService *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, err := authService.RequireAdmin(r); err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		var active int64
		db.WithContext(r.Context()).Model(&jobs.Job{}).
			Where("type = ? AND status IN ?", jobs.JobTypeAdvisoryBackfill,
				[]jobs.JobStatus{jobs.JobStatusQueued, jobs.JobStatusRunning, jobs.JobStatusRetry}).
			Count(&active)
		if active > 0 {
			http.Error(w, "advisory backfill already queued or running", http.StatusConflict)
			return
		}

		job, err := jobs.CreateJob(r.Context(), db, jobs.CreateJobInput{
			Type:        jobs.JobTypeAdvisoryBackfill,
			MaxAttempts: 1, // a partial backfill is fine — the 5-min worker mops up
		})
		if err != nil {
			http.Error(w, "failed to enqueue backfill: "+err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusAccepted, map[string]string{
			"job_id": job.ID,
			"status": string(job.Status),
		})
	}
}

// AdminAIBackfillStatusHandler reports the latest backfill job so the
// admin page can poll progress ({status, done, total} mid-run;
// {status: complete, generated, total} when finished).
// GET /api/admin/ai/backfill/status
func AdminAIBackfillStatusHandler(db *gorm.DB, authService *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, err := authService.RequireAdmin(r); err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		var job jobs.Job
		if err := db.WithContext(r.Context()).
			Where("type = ?", jobs.JobTypeAdvisoryBackfill).
			Order("created_at DESC").
			First(&job).Error; err != nil {
			writeJSON(w, http.StatusOK, map[string]any{"status": "never_run"})
			return
		}
		resp := map[string]any{
			"status":     string(job.Status),
			"created_at": job.CreatedAt,
			"error":      job.Error,
		}
		if len(job.Result) > 0 {
			var result map[string]any
			if json.Unmarshal(job.Result, &result) == nil {
				resp["result"] = result
			}
		}
		writeJSON(w, http.StatusOK, resp)
	}
}

// AdminAIModelsHandler proxies the endpoint's model list so the admin
// UI can offer a dropdown. base_url comes from the (possibly unsaved)
// form value; the stored key of the given use case authenticates,
// since the UI never holds key plaintext.
// GET /api/admin/ai/models?use_case=&base_url=
func AdminAIModelsHandler(db *gorm.DB, authService *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, err := authService.RequireAdmin(r); err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		useCase := r.URL.Query().Get("use_case")
		baseURL := r.URL.Query().Get("base_url")
		apiKey := ""
		if useCase != "" {
			if stored, err := llmadvisory.GetSettings(r.Context(), db, useCase); err == nil {
				apiKey = stored.APIKey
				if baseURL == "" {
					baseURL = stored.BaseURL
				}
			}
		}
		if baseURL == "" {
			http.Error(w, "base_url required", http.StatusBadRequest)
			return
		}
		models, err := llmadvisory.ListModels(r.Context(), baseURL, apiKey)
		if err != nil {
			writeJSON(w, http.StatusOK, map[string]any{"models": []string{}, "error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"models": models})
	}
}
