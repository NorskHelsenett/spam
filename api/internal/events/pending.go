package events

import (
	"context"
	"net/http"
	"time"
)

type approvalPayload struct {
	Approved bool   `json:"approved"`
	Role     string `json:"role"`
}

// PendingApprovalStream streams approval status updates for a pending user.
func PendingApprovalStream(loadSession func(*http.Request) (SessionInfo, error), status func(context.Context, string) (bool, string, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session, err := loadSession(r)
		if err != nil || session.UserID == "" {
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

		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-r.Context().Done():
				return
			case <-ticker.C:
				approved, role, err := status(r.Context(), session.UserID)
				if err != nil {
					return
				}
				if approved {
					_ = writeSSE(w, "approved", approvalPayload{Approved: true, Role: role})
					flusher.Flush()
					return
				}
				_ = writeSSE(w, "pending", approvalPayload{Approved: false, Role: role})
				flusher.Flush()
			}
		}
	}
}
