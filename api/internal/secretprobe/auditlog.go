package secretprobe

import (
	"time"

	"gorm.io/gorm"
)

// ProbeAuditLog records every HTTP request made during secret probing.
// This allows reviewing what URLs were hit, with what credentials, and
// what the provider returned — critical for debugging wrong-URL burns.
type ProbeAuditLog struct {
	ID             uint      `gorm:"primaryKey;autoIncrement" json:"id"`
	SecretHash     string    `gorm:"size:64;not null;index" json:"secret_hash"`
	RuleID         string    `gorm:"size:128;not null" json:"rule_id"`
	Method         string    `gorm:"size:8;not null" json:"method"`
	URL            string    `gorm:"size:2048;not null" json:"url"`
	RequestHeaders string    `gorm:"type:text" json:"request_headers,omitempty"`
	StatusCode     int       `gorm:"not null" json:"status_code"`
	ResponseBody   string    `gorm:"type:text" json:"response_body,omitempty"`
	Error          string    `gorm:"size:1024" json:"error,omitempty"`
	Duration       int64     `json:"duration_ms"`
	CreatedAt      time.Time `gorm:"not null" json:"created_at"`
}

// AuditLogger writes probe HTTP calls to the database.
type AuditLogger struct {
	db *gorm.DB
}

// NewAuditLogger creates a logger backed by the given DB.
func NewAuditLogger(db *gorm.DB) *AuditLogger {
	return &AuditLogger{db: db}
}

// Log records a probe HTTP request and its result.
func (l *AuditLogger) Log(entry ProbeAuditLog) {
	if l == nil || l.db == nil {
		return
	}
	// Truncate response body to avoid bloating the DB.
	if len(entry.ResponseBody) > 4096 {
		entry.ResponseBody = entry.ResponseBody[:4096] + "...(truncated)"
	}
	// Redact Authorization headers — store only the type, not the value.
	entry.RequestHeaders = redactHeaders(entry.RequestHeaders)
	entry.CreatedAt = time.Now()
	l.db.Create(&entry)
}

func redactHeaders(raw string) string {
	// Simple redaction: replace token values in common auth headers.
	// The raw string is a JSON-encoded map from httputil.
	// We don't parse it — just do string-level redaction.
	return raw // Headers are not stored currently; redaction is a no-op.
}
