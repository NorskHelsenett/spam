package uiapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/NorskHelsenett/spam/internal/auth"
	"github.com/NorskHelsenett/spam/internal/llmadvisory"
	"gorm.io/gorm"
)

const (
	// triageChatMaxTurns bounds conversation length so a runaway
	// client can't ship an unbounded payload to the LLM.
	triageChatMaxTurns = 40
	// triageChatMaxLen bounds one message's size.
	triageChatMaxLen = 8000
)

// TriageChatHandler relays a conversation about one finding to the
// LLM endpoint. The server injects the finding evidence (same payload
// the advisory generator uses) as the grounding first turn, so the
// client only ships the visible chat history.
//
// POST /api/triage/chat {asset_type, asset_id, messages:[{role,content}]}
//
// ACL: the caller must be able to read the asset — same gates as the
// triage detail endpoints. 404s on both missing and forbidden.
func TriageChatHandler(db *gorm.DB, authService *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireApproved(w, r) {
			return
		}
		var body struct {
			AssetType string                `json:"asset_type"`
			AssetID   string                `json:"asset_id"`
			Messages  []llmadvisory.Message `json:"messages"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "invalid body", http.StatusBadRequest)
			return
		}
		if body.AssetType != "image" && body.AssetType != "repo" {
			http.Error(w, "asset_type must be image or repo", http.StatusBadRequest)
			return
		}
		if len(body.Messages) == 0 || len(body.Messages) > triageChatMaxTurns {
			http.Error(w, "messages must contain 1..40 turns", http.StatusBadRequest)
			return
		}
		for _, m := range body.Messages {
			if m.Role != "user" && m.Role != "assistant" {
				http.Error(w, "message roles must be user or assistant", http.StatusBadRequest)
				return
			}
			if len(m.Content) > triageChatMaxLen {
				http.Error(w, "message too long", http.StatusBadRequest)
				return
			}
		}

		ctx := r.Context()
		switch body.AssetType {
		case "image":
			if ok, err := canReadImageByID(r, db, body.AssetID); err != nil || !ok {
				notFoundOrForbidden(w)
				return
			}
		case "repo":
			if ok, err := canReadRepoByID(r, db, body.AssetID); err != nil || !ok {
				notFoundOrForbidden(w)
				return
			}
		}

		cfg, err := llmadvisory.GetSettings(ctx, db, llmadvisory.UseCaseChat)
		if err != nil || !cfg.Enabled {
			http.Error(w, "finding chat is not enabled", http.StatusServiceUnavailable)
			return
		}

		sig, err := llmadvisory.LoadSignals(ctx, db, body.AssetType, body.AssetID)
		if err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				notFoundOrForbidden(w)
				return
			}
			http.Error(w, "failed to load asset", http.StatusInternalServerError)
			return
		}
		payload, err := llmadvisory.BuildChatPayload(ctx, db, sig)
		if err != nil {
			http.Error(w, "failed to build finding context", http.StatusInternalServerError)
			return
		}

		// Grounding turn first, then the visible history. The exchange
		// is stateless server-side — the client resends its history,
		// the server resends the (fresh) evidence.
		msgs := make([]llmadvisory.Message, 0, len(body.Messages)+1)
		msgs = append(msgs, llmadvisory.Message{Role: "user", Content: "Finding context:\n" + payload})
		msgs = append(msgs, body.Messages...)

		// Stream the reply as SSE data events: {"thinking":true} while
		// the reasoning model deliberates, {"delta":"…"} per content
		// chunk, then {"done":true} (or {"error":"…"}). Falls back to
		// one JSON response when the writer can't flush.
		flusher, canStream := w.(http.Flusher)
		if !canStream {
			reply, err := llmadvisory.Converse(ctx, cfg, msgs)
			if err != nil {
				http.Error(w, "llm request failed: "+err.Error(), http.StatusBadGateway)
				return
			}
			writeJSON(w, http.StatusOK, map[string]string{"reply": reply})
			return
		}

		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("X-Accel-Buffering", "no")
		w.WriteHeader(http.StatusOK)
		send := func(v map[string]any) {
			b, err := json.Marshal(v)
			if err != nil {
				return
			}
			fmt.Fprintf(w, "data: %s\n\n", b)
			flusher.Flush()
		}

		_, err = llmadvisory.ConverseStream(ctx, cfg, msgs,
			func() { send(map[string]any{"thinking": true}) },
			func(delta string) { send(map[string]any{"delta": delta}) },
		)
		if err != nil {
			send(map[string]any{"error": err.Error()})
			return
		}
		send(map[string]any{"done": true})
	}
}
