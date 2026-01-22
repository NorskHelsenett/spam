package server

import (
	"net/http"
	"time"

	"github.com/NorskHelsenett/spam/internal/auth"
	"github.com/NorskHelsenett/spam/internal/handlers/health"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"gorm.io/gorm"
)

// NewRouter wires the HTTP routes and middleware for the API server.
func NewRouter(db *gorm.DB, authService *auth.Service, shutdown <-chan struct{}) http.Handler {
	r := chi.NewRouter()

	// Health check endpoint without middleware to avoid noise in logs
	r.Get("/api/healthz", health.Handler(db))

	// Apply middleware to all other routes
	r.Group(func(r chi.Router) {
		r.Use(middleware.RequestID)
		r.Use(middleware.RealIP)
		r.Use(middleware.Logger)
		r.Use(middleware.Recoverer)
		r.Use(middleware.Timeout(60 * time.Second))

		r.Route("/api", func(api chi.Router) {
			if authService != nil {
				api.Route("/auth", func(authRouter chi.Router) {
					authRouter.Get("/login", authService.LoginHandler())
					authRouter.Get("/callback", authService.CallbackHandler())
					authRouter.Get("/me", authService.MeHandler())
					authRouter.Post("/logout", authService.LogoutHandler())
				})
				api.Get("/app/stream", authService.AppStreamHandler(shutdown))
			}
		})

		if spaHandler != nil {
			r.Handle("/*", spaHandler)
		}
	})

	return r
}
