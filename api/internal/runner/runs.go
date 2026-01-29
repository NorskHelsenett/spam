package runner

import (
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
)

// JobTypeCreateRun is the job type for runner jobs.
const JobTypeCreateRun = "CREATE_RUN"

// ListRunsResponse is the response for listing runs.
type ListRunsResponse struct {
	Runs       []Run `json:"runs"`
	Total      int64 `json:"total"`
	Page       int   `json:"page"`
	PerPage    int   `json:"per_page"`
	TotalPages int   `json:"total_pages"`
}

// handleListRuns lists all runs with pagination.
func (s *Server) handleListRuns(w http.ResponseWriter, r *http.Request) {
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}
	perPage, _ := strconv.Atoi(r.URL.Query().Get("per_page"))
	if perPage < 1 || perPage > 100 {
		perPage = 20
	}

	status := r.URL.Query().Get("status")

	var runs []Run
	var total int64

	query := s.db.WithContext(r.Context()).Model(&Run{}).Where("type = ?", JobTypeCreateRun)
	if status != "" {
		query = query.Where("status = ?", status)
	}

	// Get total count
	query.Count(&total)

	// Get paginated results
	offset := (page - 1) * perPage
	if err := query.Order("created_at DESC").Offset(offset).Limit(perPage).Find(&runs).Error; err != nil {
		log.Printf("failed to list runs: %v", err)
		http.Error(w, "failed to list runs", http.StatusInternalServerError)
		return
	}

	totalPages := int(total) / perPage
	if int(total)%perPage > 0 {
		totalPages++
	}

	resp := ListRunsResponse{
		Runs:       runs,
		Total:      total,
		Page:       page,
		PerPage:    perPage,
		TotalPages: totalPages,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// handleGetRun gets a single run by ID.
func (s *Server) handleGetRun(w http.ResponseWriter, r *http.Request) {
	runID := chi.URLParam(r, "id")
	if runID == "" {
		http.Error(w, "missing run ID", http.StatusBadRequest)
		return
	}

	var run Run
	if err := s.db.WithContext(r.Context()).Where("id = ?", runID).First(&run).Error; err != nil {
		http.Error(w, "run not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(run)
}

// handleCancelRun cancels a running job.
func (s *Server) handleCancelRun(w http.ResponseWriter, r *http.Request) {
	runID := chi.URLParam(r, "id")
	if runID == "" {
		http.Error(w, "missing run ID", http.StatusBadRequest)
		return
	}

	// Get the run
	var run Run
	if err := s.db.WithContext(r.Context()).Where("id = ?", runID).First(&run).Error; err != nil {
		http.Error(w, "run not found", http.StatusNotFound)
		return
	}

	// Check if run is cancellable
	if run.Status != RunStatusQueued && run.Status != RunStatusRunning {
		http.Error(w, "run cannot be cancelled in current state", http.StatusBadRequest)
		return
	}

	// Try to send cancel signal via WebSocket
	if run.Status == RunStatusRunning {
		if err := s.SendCancel(runID); err != nil {
			log.Printf("failed to send cancel signal: %v", err)
			// Continue anyway - we'll update the status
		}
	}

	// Update status to CANCELLED
	now := time.Now()
	updates := map[string]interface{}{
		"status":       RunStatusCancelled,
		"cancelled_at": now,
		"finished_at":  now,
		"updated_at":   now,
	}

	// TODO: Get user ID from auth context
	// updates["cancelled_by"] = userID

	if err := s.db.WithContext(r.Context()).Model(&Run{}).Where("id = ?", runID).Updates(updates).Error; err != nil {
		log.Printf("failed to cancel run: %v", err)
		http.Error(w, "failed to cancel run", http.StatusInternalServerError)
		return
	}

	// If K8s job exists, delete it
	if run.K8sJobName != "" && run.K8sNamespace != "" {
		// TODO: Delete K8s job
		log.Printf("TODO: delete K8s job %s/%s", run.K8sNamespace, run.K8sJobName)
	}

	// Broadcast cancellation to SSE subscribers
	s.broadcastStatus(runID)

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"cancelled"}`))
}
