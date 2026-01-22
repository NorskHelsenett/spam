package server

import (
	"net/http"
	"time"

	"github.com/NorskHelsenett/spam/internal/handlers/health"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"gorm.io/gorm"
)

// NewRouter wires the HTTP routes and middleware for the API server.
func NewRouter(db *gorm.DB) http.Handler {
	r := chi.NewRouter()

	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(60 * time.Second))

	r.Route("/api", func(api chi.Router) {
		api.Get("/healthz", health.Handler(db))
	})

	if spaHandler != nil {
		r.Handle("/*", spaHandler)
	}

	return r
}
