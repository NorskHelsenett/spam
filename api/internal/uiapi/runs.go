package uiapi

import (
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/NorskHelsenett/spam/internal/auth"
	"github.com/NorskHelsenett/spam/internal/jobs"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// RunResponse represents a run in the API response.
type RunResponse struct {
	ID          string     `json:"id"`
	Status      string     `json:"status"`
	CloneURL    string     `json:"clone_url"`
	Provider    string     `json:"provider"`
	RepoPath    string     `json:"repo_path"`
	Ref         string     `json:"ref,omitempty"`
	Error       string     `json:"error,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	StartedAt   *time.Time `json:"started_at,omitempty"`
	FinishedAt  *time.Time `json:"finished_at,omitempty"`
	K8sJobName  string     `json:"k8s_job_name,omitempty"`
}

// RunsListResponse is the response for listing runs.
type RunsListResponse struct {
	Runs       []RunResponse `json:"runs"`
	TotalCount int64         `json:"total_count"`
	Page       int           `json:"page"`
	PageSize   int           `json:"page_size"`
}

// CreateRunRequest is the request to create a new run.
type CreateRunRequest struct {
	Provider string `json:"provider"` // github, gitlab, gitea
	RepoPath string `json:"repo_path"` // owner/repo or group/project
	Ref      string `json:"ref,omitempty"` // branch or tag
	BaseURL  string `json:"base_url,omitempty"` // for gitlab/gitea custom instances
}

// CreateRunResponse is the response after creating a run.
type CreateRunResponse struct {
	ID     string `json:"id"`
	Status string `json:"status"`
}

// RunsListHandler lists all runs with pagination.
// GET /api/runs
func RunsListHandler(db *gorm.DB, authService *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, err := authService.LoadSession(r); err != nil {
			http.Error(w, "unauthenticated", http.StatusUnauthorized)
			return
		}

		page, pageSize := parsePagination(r)
		status := r.URL.Query().Get("status")
		repoPath := r.URL.Query().Get("repo_path")

		var total int64
		query := db.WithContext(r.Context()).Table("jobs").Where("type = ?", jobs.JobTypeCreateRun)
		if status != "" {
			query = query.Where("status = ?", status)
		}
		if repoPath != "" {
			// Search in payload JSON for matching repo path
			query = query.Where("payload::text LIKE ?", "%"+repoPath+"%")
		}
		query.Count(&total)

		var jobRecords []struct {
			ID         string
			Status     string
			Payload    []byte
			Error      string
			CreatedAt  time.Time
			LockedAt   *time.Time
			FinishedAt *time.Time
			K8sJobName string `gorm:"column:k8s_job_name"`
		}

		offset := (page - 1) * pageSize
		if err := query.Select("id, status, payload, error, created_at, locked_at, finished_at, k8s_job_name").
			Order("created_at DESC").
			Offset(offset).
			Limit(pageSize).
			Find(&jobRecords).Error; err != nil {
			log.Printf("failed to list runs: %v", err)
			http.Error(w, "failed to list runs", http.StatusInternalServerError)
			return
		}

		runs := make([]RunResponse, 0, len(jobRecords))
		for _, job := range jobRecords {
			var payload jobs.CreateRunPayload
			if len(job.Payload) > 0 {
				json.Unmarshal(job.Payload, &payload)
			}

			runs = append(runs, RunResponse{
				ID:         job.ID,
				Status:     job.Status,
				CloneURL:   payload.CloneURL,
				Provider:   payload.Provider,
				RepoPath:   extractRepoPath(payload.CloneURL),
				Ref:        payload.Ref,
				Error:      job.Error,
				CreatedAt:  job.CreatedAt,
				StartedAt:  job.LockedAt,
				FinishedAt: job.FinishedAt,
				K8sJobName: job.K8sJobName,
			})
		}

		writeJSON(w, http.StatusOK, RunsListResponse{
			Runs:       runs,
			TotalCount: total,
			Page:       page,
			PageSize:   pageSize,
		})
	}
}

// RunsCreateHandler creates a new run.
// POST /api/runs
func RunsCreateHandler(db *gorm.DB, authService *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, err := authService.LoadSession(r); err != nil {
			http.Error(w, "unauthenticated", http.StatusUnauthorized)
			return
		}

		var req CreateRunRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}

		if req.Provider == "" || req.RepoPath == "" {
			http.Error(w, "provider and repo_path are required", http.StatusBadRequest)
			return
		}

		// Build clone URL based on provider
		cloneURL := buildCloneURL(req.Provider, req.RepoPath, req.BaseURL)
		if cloneURL == "" {
			http.Error(w, "invalid provider or repo_path", http.StatusBadRequest)
			return
		}

		// Create job payload
		payload := jobs.CreateRunPayload{
			Provider: req.Provider,
			CloneURL: cloneURL,
			Ref:      req.Ref,
		}

		payloadBytes, err := json.Marshal(payload)
		if err != nil {
			http.Error(w, "failed to create run", http.StatusInternalServerError)
			return
		}

		// Create job record
		jobID := uuid.New().String()
		now := time.Now()
		job := map[string]interface{}{
			"id":           jobID,
			"type":         jobs.JobTypeCreateRun,
			"status":       "QUEUED",
			"payload":      payloadBytes,
			"attempts":     0,
			"max_attempts": 3,
			"run_at":       now,
			"created_at":   now,
			"updated_at":   now,
		}

		if err := db.WithContext(r.Context()).Table("jobs").Create(job).Error; err != nil {
			log.Printf("failed to create run: %v", err)
			http.Error(w, "failed to create run", http.StatusInternalServerError)
			return
		}

		writeJSON(w, http.StatusCreated, CreateRunResponse{
			ID:     jobID,
			Status: "QUEUED",
		})
	}
}

// RunGetHandler gets a single run by ID.
// GET /api/runs/{id}
func RunGetHandler(db *gorm.DB, authService *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, err := authService.LoadSession(r); err != nil {
			http.Error(w, "unauthenticated", http.StatusUnauthorized)
			return
		}

		runID := r.PathValue("id")
		if runID == "" {
			http.Error(w, "run ID is required", http.StatusBadRequest)
			return
		}

		var job struct {
			ID         string
			Status     string
			Payload    []byte
			Error      string
			CreatedAt  time.Time
			LockedAt   *time.Time
			FinishedAt *time.Time
			K8sJobName string `gorm:"column:k8s_job_name"`
		}

		if err := db.WithContext(r.Context()).Table("jobs").
			Where("id = ? AND type = ?", runID, jobs.JobTypeCreateRun).
			First(&job).Error; err != nil {
			if err == gorm.ErrRecordNotFound {
				http.Error(w, "run not found", http.StatusNotFound)
				return
			}
			http.Error(w, "failed to get run", http.StatusInternalServerError)
			return
		}

		var payload jobs.CreateRunPayload
		if len(job.Payload) > 0 {
			json.Unmarshal(job.Payload, &payload)
		}

		writeJSON(w, http.StatusOK, RunResponse{
			ID:         job.ID,
			Status:     job.Status,
			CloneURL:   payload.CloneURL,
			Provider:   payload.Provider,
			RepoPath:   extractRepoPath(payload.CloneURL),
			Ref:        payload.Ref,
			Error:      job.Error,
			CreatedAt:  job.CreatedAt,
			StartedAt:  job.LockedAt,
			FinishedAt: job.FinishedAt,
			K8sJobName: job.K8sJobName,
		})
	}
}

// buildCloneURL constructs a clone URL based on provider and repo path.
func buildCloneURL(provider, repoPath, baseURL string) string {
	switch provider {
	case "github":
		return "https://github.com/" + repoPath + ".git"
	case "gitlab":
		if baseURL != "" {
			return baseURL + "/" + repoPath + ".git"
		}
		return "https://gitlab.com/" + repoPath + ".git"
	case "gitea", "forgejo":
		if baseURL == "" {
			return ""
		}
		return baseURL + "/" + repoPath + ".git"
	default:
		return ""
	}
}

// extractRepoPath extracts the repo path from a clone URL.
func extractRepoPath(cloneURL string) string {
	// Remove protocol
	path := cloneURL
	for _, prefix := range []string{"https://", "http://", "git@"} {
		if len(path) > len(prefix) && path[:len(prefix)] == prefix {
			path = path[len(prefix):]
			break
		}
	}

	// Remove host
	if idx := indexByte(path, '/'); idx != -1 {
		path = path[idx+1:]
	}

	// Remove .git suffix
	if len(path) > 4 && path[len(path)-4:] == ".git" {
		path = path[:len(path)-4]
	}

	return path
}

func indexByte(s string, c byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			return i
		}
	}
	return -1
}
