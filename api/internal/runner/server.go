package runner

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/NorskHelsenett/spam/internal/auth"
	"github.com/NorskHelsenett/spam/internal/cache"
	"github.com/NorskHelsenett/spam/internal/config"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"gorm.io/gorm"
)

// Server is the runner HTTP server that handles runner callbacks and client requests.
type Server struct {
	cfg        config.RunnerConfig
	db         *gorm.DB
	httpServer *http.Server
	k8sClient  *K8sClient
	cache      cache.Store

	// WebSocket connections for active runs (runID -> connection)
	wsConnsMu sync.RWMutex
	wsConns   map[string]*WSConn
}

// NewServer creates a new runner server.
func NewServer(cfg config.RunnerConfig, db *gorm.DB, k8sClient *K8sClient, cacheStore cache.Store) *Server {
	return &Server{
		cfg:       cfg,
		db:        db,
		k8sClient: k8sClient,
		cache:     cacheStore,
		wsConns:   make(map[string]*WSConn),
	}
}

// Start starts the HTTP server.
func (s *Server) Start(ctx context.Context) error {
	r := chi.NewRouter()

	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	// Health check
	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	// Runner endpoints (internal, token auth)
	r.Route("/runner", func(r chi.Router) {
		r.Get("/ws", s.handleWebSocket)
		r.HandleFunc("/git/{run_id}/*", s.handleGitProxy)
		r.Group(func(r chi.Router) {
			r.Use(middleware.Timeout(60 * time.Second))
			r.Post("/results", s.handleResults)
		})
		r.Group(func(r chi.Router) {
			// Image-scan results can be larger than git-clone results
			// (SBOM + grype JSON + cosign + labels + betterleaks); give
			// the handler more breathing room on slower upstream writes.
			r.Use(middleware.Timeout(180 * time.Second))
			r.Post("/image-results", s.handleImageResults)
		})
	})

	// Trivy scanner endpoints are served by the worker listener so scanner jobs
	// can talk directly to the worker service.
	r.Group(func(r chi.Router) {
		r.Use(auth.HMACMiddleware(string(s.cfg.HMACKey)))
		r.Use(middleware.Timeout(60 * time.Second))
		r.Get("/api/sboms/{id}/download", sbomDownloadHandler(s.db))
		r.Get("/api/trivy/next", trivyScanNextHandler(s.db))
		r.Post("/api/trivy/result/{sbom_id}", trivyScanResultHandler(s.db))
		r.Get("/api/trivy/manifests/{repo_id}", trivyManifestsHandler(s.db))
		r.Post("/api/tool-versions", toolVersionsHandler(s.db))
		// Image scanner endpoints — the dedicated spam-image-scanner pod
		// leases IMAGE_SCAN jobs via /next, uploads artifacts via
		// /runner/image-results (run-token-auth), and reports terminal
		// status via /complete.
		r.Get("/api/image-scans/next", s.handleImageScanNext)
		r.Post("/api/image-scans/{job_id}/complete", s.handleImageScanComplete)
	})

	addr := fmt.Sprintf(":%d", s.cfg.HTTPPort)
	s.httpServer = &http.Server{
		Addr:    addr,
		Handler: r,
	}

	log.Printf("runner server listening on %s", addr)

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		s.httpServer.Shutdown(shutdownCtx)
	}()

	if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

// GetWSConn returns the WebSocket connection for a run.
func (s *Server) GetWSConn(runID string) *WSConn {
	s.wsConnsMu.RLock()
	defer s.wsConnsMu.RUnlock()
	return s.wsConns[runID]
}

// SetWSConn sets the WebSocket connection for a run.
func (s *Server) SetWSConn(runID string, conn *WSConn) {
	s.wsConnsMu.Lock()
	s.wsConns[runID] = conn
	s.wsConnsMu.Unlock()
}

// RemoveWSConn removes the WebSocket connection for a run.
func (s *Server) RemoveWSConn(runID string) {
	s.wsConnsMu.Lock()
	delete(s.wsConns, runID)
	s.wsConnsMu.Unlock()
}

// SendCancel sends a cancellation signal to a running job.
func (s *Server) SendCancel(runID string) error {
	conn := s.GetWSConn(runID)
	if conn == nil {
		return fmt.Errorf("no active connection for run %s", runID)
	}
	return conn.SendCancel()
}

// handleGetK8sLogs retrieves logs directly from the Kubernetes pod.
func (s *Server) handleGetK8sLogs(w http.ResponseWriter, r *http.Request) {
	runID := chi.URLParam(r, "id")
	if runID == "" {
		http.Error(w, "missing run ID", http.StatusBadRequest)
		return
	}

	// Get run from database
	var run Run
	if err := s.db.WithContext(r.Context()).Where("id = ?", runID).First(&run).Error; err != nil {
		http.Error(w, "run not found", http.StatusNotFound)
		return
	}

	if run.K8sJobName == "" || run.K8sNamespace == "" {
		http.Error(w, "run has no associated Kubernetes job", http.StatusBadRequest)
		return
	}

	// Parse tail parameter (default 1000 lines)
	tailLines := int64(1000)
	if tailStr := r.URL.Query().Get("tail"); tailStr != "" {
		if n, err := fmt.Sscanf(tailStr, "%d", &tailLines); err == nil && n == 1 && tailLines > 0 {
			// parsed successfully
		}
	}

	// Get logs from Kubernetes
	logs, err := s.k8sClient.GetPodLogs(r.Context(), run.K8sJobName, run.K8sNamespace, &tailLines)
	if err != nil {
		log.Printf("failed to get pod logs: %v", err)
		http.Error(w, fmt.Sprintf("failed to retrieve logs: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(logs))
}

// handleGetK8sStatus retrieves the Kubernetes job status.
func (s *Server) handleGetK8sStatus(w http.ResponseWriter, r *http.Request) {
	runID := chi.URLParam(r, "id")
	if runID == "" {
		http.Error(w, "missing run ID", http.StatusBadRequest)
		return
	}

	// Get run from database
	var run Run
	if err := s.db.WithContext(r.Context()).Where("id = ?", runID).First(&run).Error; err != nil {
		http.Error(w, "run not found", http.StatusNotFound)
		return
	}

	if run.K8sJobName == "" || run.K8sNamespace == "" {
		http.Error(w, "run has no associated Kubernetes job", http.StatusBadRequest)
		return
	}

	// Get job status from Kubernetes
	job, err := s.k8sClient.GetJobStatus(r.Context(), run.K8sJobName, run.K8sNamespace)
	if err != nil {
		log.Printf("failed to get job status: %v", err)
		http.Error(w, fmt.Sprintf("failed to retrieve job status: %v", err), http.StatusInternalServerError)
		return
	}

	// Return simplified status
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `{"job_name":"%s","namespace":"%s","active":%d,"succeeded":%d,"failed":%d}`,
		job.Name, job.Namespace, job.Status.Active, job.Status.Succeeded, job.Status.Failed)
}
