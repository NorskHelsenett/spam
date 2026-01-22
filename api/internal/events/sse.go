package events

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"
)

type heartbeatPayload struct {
	Timestamp string `json:"timestamp"`
	SessionID string `json:"session_id"`
	Subject   string `json:"subject,omitempty"`
	Name      string `json:"name,omitempty"`
	Email     string `json:"email,omitempty"`
}

type shutdownPayload struct {
	Message string `json:"message"`
}

type readyPayload struct {
	SessionID string `json:"session_id"`
	Subject   string `json:"subject,omitempty"`
	Name      string `json:"name,omitempty"`
	Email     string `json:"email,omitempty"`
}

type SessionInfo struct {
	ID      string
	UserID  string
	Subject string
	Name    string
	Email   string
}

// AppStreamHandler streams server-sent events for authenticated app sessions.
func AppStreamHandler(loadSession func(*http.Request) (SessionInfo, error), shutdown <-chan struct{}) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session, err := loadSession(r)
		if err != nil {
			http.Error(w, "unauthenticated", http.StatusUnauthorized)
			return
		}

		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "streaming unsupported", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		w.Header().Set("X-Accel-Buffering", "no")

		if err := writeSSE(w, "ready", readyPayload{
			SessionID: session.ID,
			Subject:   session.Subject,
			Name:      session.Name,
			Email:     session.Email,
		}); err != nil {
			return
		}
		if _, err := fmt.Fprint(w, "retry: 5000\n\n"); err != nil {
			return
		}
		flusher.Flush()

		heartbeat := time.NewTicker(20 * time.Second)
		defer heartbeat.Stop()

		for {
			select {
			case <-r.Context().Done():
				return
			case <-shutdown:
				if err := writeSSE(w, "shutting_down", shutdownPayload{Message: "server shutting down"}); err != nil {
					return
				}
				flusher.Flush()
				return
			case tick := <-heartbeat.C:
				payload := heartbeatPayload{
					Timestamp: tick.UTC().Format(time.RFC3339),
					SessionID: session.ID,
					Subject:   session.Subject,
					Name:      session.Name,
					Email:     session.Email,
				}
				if err := writeSSE(w, "heartbeat", payload); err != nil {
					return
				}
				flusher.Flush()
				log.Printf("sse heartbeat sent: session=%s subject=%s", session.ID, session.Subject)
			}
		}
	}
}

func writeSSE(w http.ResponseWriter, event string, payload interface{}) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	if event != "" {
		if _, err := fmt.Fprintf(w, "event: %s\n", event); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintf(w, "data: %s\n\n", data); err != nil {
		return err
	}
	return nil
}
