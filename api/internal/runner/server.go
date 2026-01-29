package runner

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

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

	// WebSocket connections for active runs (runID -> connection)
	wsConnsMu sync.RWMutex
	wsConns   map[string]*WSConn

	// SSE subscribers for log streaming (runID -> subscribers)
	sseSubsMu sync.RWMutex
	sseSubs   map[string]map[chan LogEvent]struct{}
}

// LogEvent represents a log event sent via SSE.
type LogEvent struct {
	Line      string    `json:"line"`
	Timestamp time.Time `json:"ts"`
}

// NewServer creates a new runner server.
func NewServer(cfg config.RunnerConfig, db *gorm.DB) *Server {
	return &Server{
		cfg:     cfg,
		db:      db,
		wsConns: make(map[string]*WSConn),
		sseSubs: make(map[string]map[chan LogEvent]struct{}),
	}
}

// Start starts the HTTP server.
func (s *Server) Start(ctx context.Context) error {
	r := chi.NewRouter()

	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(60 * time.Second))

	// Health check
	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	// Runner endpoints (internal, token auth)
	r.Route("/runner", func(r chi.Router) {
		r.Get("/ws", s.handleWebSocket)
		r.Post("/token", s.handleTokenExchange)
		r.Post("/results", s.handleResults)
	})

	// Client/API endpoints
	r.Route("/runs", func(r chi.Router) {
		r.Get("/", s.handleListRuns)
		r.Get("/{id}", s.handleGetRun)
		r.Get("/{id}/logs", s.handleStreamLogs)
		r.Post("/{id}/cancel", s.handleCancelRun)
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

// BroadcastLog sends a log line to all SSE subscribers for a run.
func (s *Server) BroadcastLog(runID string, line string, ts time.Time) {
	s.sseSubsMu.RLock()
	subs, ok := s.sseSubs[runID]
	s.sseSubsMu.RUnlock()

	if !ok {
		return
	}

	event := LogEvent{Line: line, Timestamp: ts}

	s.sseSubsMu.RLock()
	for ch := range subs {
		select {
		case ch <- event:
		default:
			// Channel full, skip
		}
	}
	s.sseSubsMu.RUnlock()
}

// SubscribeLogs subscribes to log events for a run.
func (s *Server) SubscribeLogs(runID string) chan LogEvent {
	ch := make(chan LogEvent, 100)

	s.sseSubsMu.Lock()
	if s.sseSubs[runID] == nil {
		s.sseSubs[runID] = make(map[chan LogEvent]struct{})
	}
	s.sseSubs[runID][ch] = struct{}{}
	s.sseSubsMu.Unlock()

	return ch
}

// UnsubscribeLogs unsubscribes from log events for a run.
func (s *Server) UnsubscribeLogs(runID string, ch chan LogEvent) {
	s.sseSubsMu.Lock()
	if subs, ok := s.sseSubs[runID]; ok {
		delete(subs, ch)
		if len(subs) == 0 {
			delete(s.sseSubs, runID)
		}
	}
	s.sseSubsMu.Unlock()
	close(ch)
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
