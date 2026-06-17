package health

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"

	"gorm.io/gorm"
)

type response struct {
	Status string `json:"status"`
	Error  string `json:"error,omitempty"`
}

// LivenessHandler reports process liveness only. It deliberately does NOT
// touch the database: a liveness probe must never restart the pod just
// because the DB is slow or contended — doing so turned a busy DB into a
// refresh/restart death spiral. A genuinely wedged process still fails this
// because the HTTP server stops accepting connections.
func LivenessHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeHealth(w, http.StatusOK, response{Status: "ok"})
	}
}

// ReadinessHandler reports whether this replica can serve real traffic: the
// database is reachable AND the base materialized views are populated.
// Gating readiness (not liveness) on MV state lets HTTP and the liveness
// probe come up immediately while the views populate in the background;
// Kubernetes withholds traffic from the replica until ready returns true.
//
// ready may be nil (then only DB reachability is checked).
func ReadinessHandler(db *gorm.DB, ready func(context.Context) (bool, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if db != nil {
			sqlDB, err := db.DB()
			if err != nil {
				writeHealth(w, http.StatusServiceUnavailable, response{Status: "db_unreachable", Error: err.Error()})
				return
			}
			if err := sqlDB.PingContext(r.Context()); err != nil {
				writeHealth(w, http.StatusServiceUnavailable, response{Status: "db_unreachable", Error: err.Error()})
				return
			}
		}
		if ready != nil {
			ok, err := ready(r.Context())
			if err != nil {
				writeHealth(w, http.StatusServiceUnavailable, response{Status: "not_ready", Error: err.Error()})
				return
			}
			if !ok {
				writeHealth(w, http.StatusServiceUnavailable, response{Status: "populating"})
				return
			}
		}
		writeHealth(w, http.StatusOK, response{Status: "ok"})
	}
}

func writeHealth(w http.ResponseWriter, code int, res response) {
	var buffer bytes.Buffer
	if err := json.NewEncoder(&buffer).Encode(res); err != nil {
		http.Error(w, "health response encoding failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_, _ = w.Write(buffer.Bytes())
}
