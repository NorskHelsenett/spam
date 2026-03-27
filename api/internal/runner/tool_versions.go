package runner

import (
	"encoding/json"
	"net/http"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// ScannerVersion stores the reported tool versions for a scanner component.
type ScannerVersion struct {
	Source    string          `gorm:"primaryKey;size:64" json:"source"` // e.g. "runner", "trivy-scanner"
	Versions json.RawMessage `gorm:"type:jsonb;not null" json:"versions"`
	UpdatedAt time.Time      `json:"updated_at"`
}

func (ScannerVersion) TableName() string {
	return "scanner_versions"
}

type toolVersionPayload struct {
	Source   string        `json:"source"`
	Versions []ToolVersion `json:"versions"`
}

// toolVersionsHandler stores tool versions reported by scanners.
// POST /api/tool-versions
func toolVersionsHandler(db *gorm.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var payload toolVersionPayload
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			http.Error(w, "invalid body", http.StatusBadRequest)
			return
		}
		if payload.Source == "" || len(payload.Versions) == 0 {
			http.Error(w, "source and versions required", http.StatusBadRequest)
			return
		}

		versionsJSON, _ := json.Marshal(payload.Versions)
		record := ScannerVersion{
			Source:    payload.Source,
			Versions: versionsJSON,
			UpdatedAt: time.Now(),
		}

		if err := db.WithContext(r.Context()).
			Clauses(clause.OnConflict{
				Columns:   []clause.Column{{Name: "source"}},
				DoUpdates: clause.AssignmentColumns([]string{"versions", "updated_at"}),
			}).Create(&record).Error; err != nil {
			http.Error(w, "store failed", http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusNoContent)
	}
}
