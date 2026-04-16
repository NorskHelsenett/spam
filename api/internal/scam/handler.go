package scam

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"gorm.io/datatypes"
	"gorm.io/gorm"
)

const maxBodySize = 10 << 20 // 10 MiB

// CallcenterHandler accepts a JSON array of SCAM records, validates each one,
// and bulk-inserts the accepted records. Invalid records are skipped and
// counted in the response. No authentication required — SPAM verifies
// legitimacy by cluster_id.
func CallcenterHandler(db *gorm.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		r.Body = http.MaxBytesReader(w, r.Body, maxBodySize)

		var raw []json.RawMessage
		if err := json.NewDecoder(r.Body).Decode(&raw); err != nil {
			http.Error(w, "invalid JSON: expected array of records", http.StatusBadRequest)
			return
		}
		if len(raw) == 0 {
			writeJSON(w, http.StatusOK, ingestResponse{Accepted: 0})
			return
		}

		now := time.Now().UTC()
		var records []Record
		var rejected int

		for _, item := range raw {
			var incoming Incoming
			if err := json.Unmarshal(item, &incoming); err != nil {
				rejected++
				continue
			}
			if err := validate(incoming); err != nil {
				rejected++
				continue
			}
			records = append(records, Record{
				Data:       datatypes.JSON(item),
				ReceivedAt: now,
			})
		}

		if len(records) > 0 {
			if err := db.CreateInBatches(records, 500).Error; err != nil {
				http.Error(w, "database error", http.StatusInternalServerError)
				return
			}
		}

		writeJSON(w, http.StatusOK, ingestResponse{
			Accepted: len(records),
			Rejected: rejected,
		})
	}
}

func validate(r Incoming) error {
	if r.Kind == "" {
		return fmt.Errorf("missing kind")
	}
	if !validKinds[r.Kind] {
		return fmt.Errorf("unknown kind: %s", r.Kind)
	}
	if r.Msg == "" {
		return fmt.Errorf("missing msg (event)")
	}
	if !validEvents[r.Msg] {
		return fmt.Errorf("unknown event: %s", r.Msg)
	}
	if r.ClusterID == "" {
		return fmt.Errorf("missing cluster_id")
	}
	return nil
}

// ImageSummaryHandler returns image counts grouped by cluster and registry.
func ImageSummaryHandler(db *gorm.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		type row struct {
			Cluster     string `json:"cluster"`
			ClusterID   string `json:"cluster_id"`
			Environment string `json:"environment"`
			Registry    string `json:"registry"`
			ImageCount  int64  `json:"image_count"`
		}
		var rows []row
		err := db.Raw(`
			SELECT
				data->>'cluster' AS cluster,
				data->>'cluster_id' AS cluster_id,
				data->>'environment' AS environment,
				data->>'registry' AS registry,
				COUNT(DISTINCT data->>'image') AS image_count
			FROM cluster_record
			WHERE data->>'kind' = 'Container'
			  AND data->>'msg' != 'DELETE'
			GROUP BY data->>'cluster', data->>'cluster_id', data->>'environment', data->>'registry'
			ORDER BY cluster, image_count DESC
		`).Scan(&rows).Error
		if err != nil {
			http.Error(w, "query failed", http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, rows)
	}
}

// ClusterSummaryHandler returns a high-level overview per cluster.
func ClusterSummaryHandler(db *gorm.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		type row struct {
			Cluster     string    `json:"cluster"`
			ClusterID   string    `json:"cluster_id"`
			Environment string    `json:"environment"`
			Containers  int64     `json:"containers"`
			Images      int64     `json:"images"`
			Namespaces  int64     `json:"namespaces"`
			LastSeen    time.Time `json:"last_seen"`
		}
		var rows []row
		err := db.Raw(`
			SELECT
				data->>'cluster' AS cluster,
				data->>'cluster_id' AS cluster_id,
				data->>'environment' AS environment,
				COUNT(*) FILTER (WHERE data->>'kind' = 'Container' AND data->>'msg' != 'DELETE') AS containers,
				COUNT(DISTINCT data->>'image') FILTER (WHERE data->>'kind' = 'Container' AND data->>'msg' != 'DELETE') AS images,
				COUNT(DISTINCT data->>'namespace') FILTER (WHERE data->>'kind' = 'Container' AND data->>'msg' != 'DELETE') AS namespaces,
				MAX(received_at) AS last_seen
			FROM cluster_record
			GROUP BY data->>'cluster', data->>'cluster_id', data->>'environment'
			ORDER BY last_seen DESC
		`).Scan(&rows).Error
		if err != nil {
			http.Error(w, "query failed", http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, rows)
	}
}

type ingestResponse struct {
	Accepted int `json:"accepted"`
	Rejected int `json:"rejected,omitempty"`
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}
