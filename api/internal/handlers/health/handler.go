package health

import (
	"bytes"
	"encoding/json"
	"net/http"

	"gorm.io/gorm"
)

type response struct {
	Status string `json:"status"`
	Error  string `json:"error,omitempty"`
}

// Handler returns an HTTP handler that reports application and database health.
func Handler(db *gorm.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		res := response{Status: "ok"}
		statusCode := http.StatusOK

		if db != nil {
			sqlDB, err := db.DB()
			if err != nil {
				res.Status = "db_unreachable"
				res.Error = err.Error()
				statusCode = http.StatusServiceUnavailable
			} else if err = sqlDB.PingContext(r.Context()); err != nil {
				res.Status = "db_unreachable"
				res.Error = err.Error()
				statusCode = http.StatusServiceUnavailable
			}
		}

		var buffer bytes.Buffer
		if err := json.NewEncoder(&buffer).Encode(res); err != nil {
			http.Error(w, "health response encoding failed", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(statusCode)

		_, _ = w.Write(buffer.Bytes())
	}
}
