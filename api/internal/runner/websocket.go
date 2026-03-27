package runner

import (
	"bufio"
	"context"
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/NorskHelsenett/spam/internal/jobs"
	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin: func(r *http.Request) bool {
		return true // Allow all origins for internal communication
	},
}

// ToolVersion represents a tool's version and binary digest.
type ToolVersion struct {
	Name         string `json:"name"`
	Version      string `json:"version"`
	BinaryDigest string `json:"binary_digest"`
}

// WSMessage represents a WebSocket message.
type WSMessage struct {
	Type         string        `json:"type"`
	Line         string        `json:"line,omitempty"`
	Timestamp    time.Time     `json:"ts,omitempty"`
	ExitCode     int           `json:"exit_code,omitempty"`
	CommitHash   string        `json:"commit_hash,omitempty"`
	ToolVersions []ToolVersion `json:"tool_versions,omitempty"`
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

	// Fetch and store init container (clone) logs — the main container
	// just connected, so the init container has completed.
	go s.fetchInitContainerLogs(claims.RunID)

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
			s.storeLog(r.Context(), claims.RunID, "runner", msg.Line, ts)

		case "commit_hash":
			log.Printf("received commit hash for run %s: %s", claims.RunID, msg.CommitHash)
			var run Run
			if err := s.db.WithContext(r.Context()).Where("id = ?", claims.RunID).First(&run).Error; err != nil {
				log.Printf("failed to load run for commit hash: %v", err)
				continue
			}

			var payload jobs.CreateRunPayload
			if len(run.Payload) > 0 {
				if err := json.Unmarshal(run.Payload, &payload); err != nil {
					log.Printf("failed to unmarshal run payload for commit hash: %v", err)
					continue
				}
			}

			verifiedCommitSHA, err := verifyAndPersistRunCommit(r.Context(), s.db, payload, msg.CommitHash)
			if err != nil {
				log.Printf("failed to verify commit hash for run %s: %v", claims.RunID, err)
				continue
			}

			if verifiedCommitSHA == "" {
				continue
			}

			// Store commit hash in database after it has been verified.
			if err := s.db.WithContext(r.Context()).Model(&Run{}).Where("id = ?", claims.RunID).Update("commit_hash", verifiedCommitSHA).Error; err != nil {
				log.Printf("failed to update commit hash: %v", err)
			}

		case "tool_versions":
			if len(msg.ToolVersions) > 0 {
				log.Printf("received tool versions for run %s: %d tools", claims.RunID, len(msg.ToolVersions))
				s.storeToolVersions(r.Context(), claims.RunID, msg.ToolVersions)
			}

		case "done":
			log.Printf("run completed: run_id=%s exit_code=%d", claims.RunID, msg.ExitCode)
			status := RunStatusSucceeded
			if msg.ExitCode != 0 {
				status = RunStatusFailed
			}
			if err := s.updateRunStatus(r.Context(), claims.RunID, status); err != nil {
				log.Printf("failed to update run status: %v", err)
			}
			return
		}
	}
}

// fetchInitContainerLogs retrieves logs from the clone init container via
// the K8s API and stores them as run log entries so they appear in the UI.
func (s *Server) fetchInitContainerLogs(runID string) {
	if s.k8sClient == nil || s.k8sClient.cfg.LocalMode {
		return
	}

	// Look up the K8s job name for this run
	var run Run
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := s.db.WithContext(ctx).Where("id = ?", runID).First(&run).Error; err != nil {
		log.Printf("fetch init logs: failed to load run %s: %v", runID, err)
		return
	}
	if run.K8sJobName == "" || run.K8sNamespace == "" {
		return
	}

	logs, err := s.k8sClient.GetContainerLogs(ctx, run.K8sJobName, run.K8sNamespace, "clone")
	if err != nil {
		log.Printf("fetch init logs: failed for run %s: %v", runID, err)
		return
	}

	now := time.Now()
	scanner := bufio.NewScanner(strings.NewReader(logs))
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		s.storeLog(ctx, runID, "clone", line, now)
	}
}

func (s *Server) storeToolVersions(ctx context.Context, runID string, versions []ToolVersion) {
	payload, err := json.Marshal(versions)
	if err != nil {
		log.Printf("failed to marshal tool versions: %v", err)
		return
	}

	// Store in run result JSON under the "tool_versions" key
	var raw json.RawMessage
	if err := s.db.WithContext(ctx).Table("jobs").Select("result").Where("id = ?", runID).Scan(&raw).Error; err != nil {
		log.Printf("failed to load run result: %v", err)
		return
	}

	resultMap := map[string]json.RawMessage{}
	if len(raw) > 0 {
		json.Unmarshal(raw, &resultMap)
	}
	resultMap["tool_versions"] = json.RawMessage(payload)

	merged, _ := json.Marshal(resultMap)
	if err := s.db.WithContext(ctx).Table("jobs").Where("id = ?", runID).Update("result", merged).Error; err != nil {
		log.Printf("failed to store tool versions: %v", err)
	}
}

func (s *Server) storeLog(ctx context.Context, runID, container, line string, ts time.Time) {
	logEntry := RunLog{
		RunID:     runID,
		Container: container,
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
