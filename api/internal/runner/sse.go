package runner

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
)

// SSELogEvent is the event sent via SSE.
type SSELogEvent struct {
	Line      string `json:"line"`
	Timestamp string `json:"ts"`
}

// SSEStatusEvent is the status event sent via SSE.
type SSEStatusEvent struct {
	Status   string `json:"status"`
	ExitCode int    `json:"exit_code,omitempty"`
}

// handleStreamLogs streams logs for a run via SSE.
func (s *Server) handleStreamLogs(w http.ResponseWriter, r *http.Request) {
	runID := chi.URLParam(r, "id")
	if runID == "" {
		http.Error(w, "missing run ID", http.StatusBadRequest)
		return
	}

	// Get the run to check status
	var run Run
	if err := s.db.WithContext(r.Context()).Where("id = ?", runID).First(&run).Error; err != nil {
		http.Error(w, "run not found", http.StatusNotFound)
		return
	}

	// Set SSE headers
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}

	// Get last_id parameter for resuming
	lastID, _ := strconv.ParseInt(r.URL.Query().Get("last_id"), 10, 64)

	// Send historical logs
	var logs []RunLog
	query := s.db.WithContext(r.Context()).Where("run_id = ?", runID)
	if lastID > 0 {
		query = query.Where("id > ?", lastID)
	}
	if err := query.Order("id ASC").Find(&logs).Error; err != nil {
		log.Printf("failed to fetch logs: %v", err)
	}

	for _, logEntry := range logs {
		event := SSELogEvent{
			Line:      logEntry.Line,
			Timestamp: logEntry.CreatedAt.Format("2006-01-02T15:04:05Z"),
		}
		data, _ := json.Marshal(event)
		fmt.Fprintf(w, "id: %d\n", logEntry.ID)
		fmt.Fprintf(w, "event: log\n")
		fmt.Fprintf(w, "data: %s\n\n", data)
	}
	flusher.Flush()

	// If run is already complete, send status and close
	if run.Status == RunStatusSucceeded || run.Status == RunStatusFailed || run.Status == RunStatusCancelled {
		statusEvent := SSEStatusEvent{
			Status: string(run.Status),
		}
		data, _ := json.Marshal(statusEvent)
		fmt.Fprintf(w, "event: status\n")
		fmt.Fprintf(w, "data: %s\n\n", data)
		flusher.Flush()
		return
	}

	// Subscribe to live logs
	ch := s.SubscribeLogs(runID)
	defer s.UnsubscribeLogs(runID, ch)

	// Stream live logs
	for {
		select {
		case <-r.Context().Done():
			return
		case event, ok := <-ch:
			if !ok {
				// Channel closed, run completed
				// Fetch final status
				s.db.WithContext(r.Context()).Where("id = ?", runID).First(&run)
				statusEvent := SSEStatusEvent{
					Status: string(run.Status),
				}
				data, _ := json.Marshal(statusEvent)
				fmt.Fprintf(w, "event: status\n")
				fmt.Fprintf(w, "data: %s\n\n", data)
				flusher.Flush()
				return
			}

			logEvent := SSELogEvent{
				Line:      event.Line,
				Timestamp: event.Timestamp.Format("2006-01-02T15:04:05Z"),
			}
			data, _ := json.Marshal(logEvent)
			fmt.Fprintf(w, "event: log\n")
			fmt.Fprintf(w, "data: %s\n\n", data)
			flusher.Flush()
		}
	}
}
