package runner

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin: func(r *http.Request) bool {
		return true // Allow all origins for internal communication
	},
}

// WSMessage represents a WebSocket message.
type WSMessage struct {
	Type      string    `json:"type"`
	Line      string    `json:"line,omitempty"`
	Timestamp time.Time `json:"ts,omitempty"`
	ExitCode  int       `json:"exit_code,omitempty"`
}

// WSConn wraps a WebSocket connection for a run.
type WSConn struct {
	conn   *websocket.Conn
	runID  string
	mu     sync.Mutex
	closed bool
}

// SendCancel sends a cancellation message to the runner.
func (w *WSConn) SendCancel() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return nil
	}
	return w.conn.WriteJSON(WSMessage{Type: "cancel"})
}

// Close closes the WebSocket connection.
func (w *WSConn) Close() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.closed {
		w.closed = true
		w.conn.Close()
	}
}

// handleWebSocket handles WebSocket connections from runners.
func (s *Server) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	// Validate token
	token := r.URL.Query().Get("token")
	if token == "" {
		http.Error(w, "missing token", http.StatusUnauthorized)
		return
	}

	claims, err := ValidateRunToken(s.cfg.HMACKey, token)
	if err != nil {
		log.Printf("invalid token: %v", err)
		http.Error(w, "invalid token", http.StatusUnauthorized)
		return
	}

	// Upgrade to WebSocket
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("websocket upgrade error: %v", err)
		return
	}

	wsConn := &WSConn{
		conn:  conn,
		runID: claims.RunID,
	}

	s.SetWSConn(claims.RunID, wsConn)
	defer func() {
		s.RemoveWSConn(claims.RunID)
		wsConn.Close()
	}()

	// Update run status to RUNNING
	if err := s.updateRunStatus(r.Context(), claims.RunID, RunStatusRunning); err != nil {
		log.Printf("failed to update run status: %v", err)
	}

	log.Printf("runner connected: run_id=%s", claims.RunID)

	// Read messages from runner
	for {
		_, message, err := conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				log.Printf("websocket read error: %v", err)
			}
			break
		}

		var msg WSMessage
		if err := json.Unmarshal(message, &msg); err != nil {
			log.Printf("invalid message: %v", err)
			continue
		}

		switch msg.Type {
		case "log":
			ts := msg.Timestamp
			if ts.IsZero() {
				ts = time.Now()
			}
			// Store log in database
			s.storeLog(r.Context(), claims.RunID, msg.Line, ts)
			// Broadcast to SSE subscribers
			s.BroadcastLog(claims.RunID, msg.Line, ts)

		case "done":
			log.Printf("run completed: run_id=%s exit_code=%d", claims.RunID, msg.ExitCode)
			status := RunStatusSucceeded
			if msg.ExitCode != 0 {
				status = RunStatusFailed
			}
			if err := s.updateRunStatus(r.Context(), claims.RunID, status); err != nil {
				log.Printf("failed to update run status: %v", err)
			}
			// Broadcast completion to SSE subscribers
			s.broadcastStatus(claims.RunID)
			return
		}
	}
}

func (s *Server) storeLog(ctx context.Context, runID, line string, ts time.Time) {
	logEntry := RunLog{
		RunID:     runID,
		Line:      line,
		CreatedAt: ts,
	}
	if err := s.db.WithContext(ctx).Create(&logEntry).Error; err != nil {
		log.Printf("failed to store log: %v", err)
	}
}

func (s *Server) updateRunStatus(ctx context.Context, runID string, status RunStatus) error {
	updates := map[string]interface{}{
		"status":     status,
		"updated_at": time.Now(),
	}

	switch status {
	case RunStatusRunning:
		now := time.Now()
		updates["locked_at"] = now
		updates["last_attempted_at"] = now
	case RunStatusSucceeded, RunStatusFailed, RunStatusCancelled:
		now := time.Now()
		updates["finished_at"] = now
	}

	return s.db.WithContext(ctx).Model(&Run{}).Where("id = ?", runID).Updates(updates).Error
}

func (s *Server) broadcastStatus(runID string) {
	// Send a special status event to SSE subscribers
	s.sseSubsMu.RLock()
	subs, ok := s.sseSubs[runID]
	s.sseSubsMu.RUnlock()

	if !ok {
		return
	}

	// Close all subscriber channels to signal completion
	s.sseSubsMu.Lock()
	for ch := range subs {
		close(ch)
	}
	delete(s.sseSubs, runID)
	s.sseSubsMu.Unlock()
}
