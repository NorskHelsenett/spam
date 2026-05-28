// Package audit records admin-level reads of sensitive surfaces
// (secret findings, provider PAT metadata, raw run secrets). It is
// intentionally append-only and does not enforce or infer access
// control — callers decide what to log.
package audit

import (
	"context"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type Log struct {
	ID        string    `gorm:"primaryKey;size:36" json:"id"`
	UserID    string    `gorm:"size:36;index" json:"user_id,omitempty"`
	Action    string    `gorm:"size:64;not null;index" json:"action"`
	Resource  string    `gorm:"size:256" json:"resource,omitempty"`
	Method    string    `gorm:"size:8" json:"method,omitempty"`
	Status    int       `gorm:"index" json:"status"`
	At        time.Time `gorm:"not null;index" json:"at"`
	IP        string    `gorm:"size:64" json:"ip,omitempty"`
	UserAgent string    `gorm:"size:255" json:"user_agent,omitempty"`
}

func (Log) TableName() string { return "audit_log" }

// RecordRequest is a convenience wrapper for handlers that want to
// audit a specific read after-the-fact (e.g. conditional on the
// response containing sensitive data). Pulls IP / UA / method off the
// request the same way Middleware does, so single audit entries match
// the shape produced by the middleware-wrapped routes.
func RecordRequest(db *gorm.DB, r *http.Request, userID, action, resource string, status int) {
	Record(db, Log{
		UserID:    userID,
		Action:    action,
		Resource:  resource,
		Method:    r.Method,
		Status:    status,
		IP:        clientIP(r),
		UserAgent: truncate(r.UserAgent(), 255),
	})
}

// Record writes an audit entry asynchronously. Failures are logged but
// never propagated — audit must not fail the user-facing request.
func Record(db *gorm.DB, entry Log) {
	if db == nil {
		return
	}
	if entry.ID == "" {
		entry.ID = uuid.NewString()
	}
	if entry.At.IsZero() {
		entry.At = time.Now().UTC()
	}
	go func(e Log) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := db.WithContext(ctx).Create(&e).Error; err != nil {
			log.Printf("audit: write %s: %v", e.Action, err)
		}
	}(entry)
}

// UserIDResolver returns the authenticated user id for the request, or
// "" if unavailable. Kept as a callback so this package does not import
// the auth package (and auth can freely import us later if needed).
type UserIDResolver func(r *http.Request) string

// Middleware records a successful (2xx) response under the wrapped
// subrouter as an audit entry with the given action label.
func Middleware(db *gorm.DB, resolve UserIDResolver, action string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ww := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(ww, r)
			if ww.status >= 200 && ww.status < 300 {
				var userID string
				if resolve != nil {
					userID = resolve(r)
				}
				Record(db, Log{
					UserID:    userID,
					Action:    action,
					Resource:  r.URL.Path,
					Method:    r.Method,
					Status:    ww.status,
					IP:        clientIP(r),
					UserAgent: truncate(r.UserAgent(), 255),
				})
			}
		})
	}
}

type statusRecorder struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (s *statusRecorder) WriteHeader(code int) {
	if !s.wroteHeader {
		s.status = code
		s.wroteHeader = true
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	if !s.wroteHeader {
		s.wroteHeader = true
	}
	return s.ResponseWriter.Write(b)
}

func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if comma := strings.Index(xff, ","); comma >= 0 {
			return strings.TrimSpace(xff[:comma])
		}
		return strings.TrimSpace(xff)
	}
	if r.RemoteAddr == "" {
		return ""
	}
	if colon := strings.LastIndex(r.RemoteAddr, ":"); colon >= 0 {
		return r.RemoteAddr[:colon]
	}
	return r.RemoteAddr
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max]
}
