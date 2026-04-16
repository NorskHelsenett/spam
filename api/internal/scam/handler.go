package scam

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/NorskHelsenett/spam/internal/events"
	"gorm.io/datatypes"
	"gorm.io/gorm"
)

const maxBodySize = 10 << 20 // 10 MiB

// resourceKeyExpr is the PostgreSQL expression that computes the unique
// resource+event identity from the JSONB data column. Matches the expression index.
// Includes msg so each lifecycle event (INITIAL, UPDATE, DELETE) is a separate row.
const resourceKeyExpr = `(
	(data->>'cluster_id') || ':' || (data->>'kind') || ':' || (data->>'msg') || ':' ||
	CASE WHEN data->>'kind' = 'Container'
	     THEN (data->>'pod_uid') || '/' || (data->>'container')
	     ELSE COALESCE(data->>'uid', '')
	END
)`

// CallcenterHandler accepts a JSON array of SCAM records, validates each one,
// and upserts live-state rows. DELETE events are stored (not physically removed)
// so the history is preserved. No authentication required.
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
		type upsertItem struct {
			data datatypes.JSON
		}
		var items []upsertItem
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
			items = append(items, upsertItem{data: datatypes.JSON(item)})
		}

		if len(items) > 0 {
			for i := 0; i < len(items); i += 500 {
				end := i + 500
				if end > len(items) {
					end = len(items)
				}
				batch := items[i:end]

				var sb strings.Builder
				args := make([]any, 0, len(batch)*2)
				sb.WriteString("INSERT INTO cluster_record (id, data, received_at) VALUES ")
				for j, u := range batch {
					if j > 0 {
						sb.WriteString(", ")
					}
					sb.WriteString("(gen_random_uuid(), ?, ?)")
					args = append(args, u.data, now)
				}
				sb.WriteString(` ON CONFLICT (`)
				sb.WriteString(resourceKeyExpr)
				sb.WriteString(`) WHERE (data->>'cluster_id') IS NOT NULL
					DO UPDATE SET data = EXCLUDED.data, received_at = EXCLUDED.received_at`)

				if err := db.Exec(sb.String(), args...).Error; err != nil {
					http.Error(w, "database error", http.StatusInternalServerError)
					return
				}
			}

			payload, _ := json.Marshal(map[string]any{
				"accepted": len(items),
				"rejected": rejected,
			})
			events.DispatchStreamEvent(events.StreamEventScamIngest, payload)
		}

		writeJSON(w, http.StatusOK, ingestResponse{
			Accepted: len(items),
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
	if r.Kind == "Container" {
		if r.PodUID == "" || r.Container == "" {
			return fmt.Errorf("Container record missing pod_uid or container")
		}
	} else {
		if r.UID == "" {
			return fmt.Errorf("%s record missing uid", r.Kind)
		}
	}
	return nil
}

// --- Query handlers (authenticated) ---

// ClusterSummaryHandler returns a high-level overview per cluster.
func ClusterSummaryHandler(db *gorm.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		type row struct {
			Cluster      string    `json:"cluster"`
			ClusterID    string    `json:"cluster_id"`
			Environment  string    `json:"environment"`
			Containers   int64     `json:"containers"`
			Images       int64     `json:"images"`
			Namespaces   int64     `json:"namespaces"`
			IngressCount int64     `json:"ingress_count"`
			LastSeen     time.Time `json:"last_seen"`
		}
		var rows []row
		err := db.Raw(`
			SELECT
				data->>'cluster'     AS cluster,
				data->>'cluster_id'  AS cluster_id,
				data->>'environment' AS environment,
				COUNT(*) FILTER (WHERE data->>'kind' = 'Container'
					AND data->>'msg' != 'DELETE') AS containers,
				COUNT(DISTINCT CONCAT(data->>'registry', '/', data->>'image', '@', data->>'digest'))
					FILTER (WHERE data->>'kind' = 'Container'
						AND data->>'msg' != 'DELETE'
						AND COALESCE(data->>'digest','') != '') AS images,
				COUNT(DISTINCT data->>'namespace')
					FILTER (WHERE data->>'kind' = 'Container'
						AND data->>'msg' != 'DELETE') AS namespaces,
				COUNT(DISTINCT data->>'uid')
					FILTER (WHERE data->>'kind' IN ('Ingress','HTTPRoute','GRPCRoute','IngressRoute','IngressRouteTCP')
						AND data->>'msg' != 'DELETE') AS ingress_count,
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

// RegistryDistributionHandler returns unique image counts by registry.
func RegistryDistributionHandler(db *gorm.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		type row struct {
			Registry   string `json:"registry"`
			ImageCount int64  `json:"image_count"`
		}
		var rows []row
		err := db.Raw(`
			SELECT
				COALESCE(NULLIF(data->>'registry', ''), 'Docker Hub') AS registry,
				COUNT(DISTINCT CONCAT(data->>'registry', '/', data->>'image', '@', data->>'digest')) AS image_count
			FROM cluster_record
			WHERE data->>'kind' = 'Container'
			  AND data->>'msg' != 'DELETE'
			  AND COALESCE(data->>'digest', '') != ''
			GROUP BY COALESCE(NULLIF(data->>'registry', ''), 'Docker Hub')
			ORDER BY image_count DESC
		`).Scan(&rows).Error
		if err != nil {
			http.Error(w, "query failed", http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, rows)
	}
}

// ExposureHandler returns internet vs internal resource counts.
func ExposureHandler(db *gorm.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		type result struct {
			InternetExposed  int64 `json:"internet_exposed"`
			InternalServices int64 `json:"internal_services"`
		}
		var res result
		err := db.Raw(`
			SELECT
				COUNT(DISTINCT data->>'uid') FILTER (
					WHERE data->>'kind' IN ('Ingress','HTTPRoute','GRPCRoute','IngressRoute','IngressRouteTCP')
					  AND data->>'msg' != 'DELETE'
				) AS internet_exposed,
				COUNT(DISTINCT data->>'uid') FILTER (
					WHERE data->>'kind' = 'Service'
					  AND data->>'msg' != 'DELETE'
				) AS internal_services
			FROM cluster_record
		`).Scan(&res).Error
		if err != nil {
			http.Error(w, "query failed", http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, res)
	}
}

// ImageDetailHandler returns images grouped by registry/image/digest with tags.
func ImageDetailHandler(db *gorm.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		type row struct {
			Registry       string    `json:"registry"`
			Image          string    `json:"image"`
			Digest         string    `json:"digest"`
			Tags           string    `json:"tags"` // comma-separated
			ClusterCount   int64     `json:"cluster_count"`
			NamespaceCount int64     `json:"namespace_count"`
			ContainerCount int64     `json:"container_count"`
			LastSeen       time.Time `json:"last_seen"`
		}
		var rows []row
		err := db.Raw(`
			SELECT
				COALESCE(NULLIF(data->>'registry', ''), 'Docker Hub') AS registry,
				data->>'image' AS image,
				data->>'digest' AS digest,
				STRING_AGG(DISTINCT data->>'tag', ',' ORDER BY data->>'tag')
					FILTER (WHERE COALESCE(data->>'tag', '') != '') AS tags,
				COUNT(DISTINCT data->>'cluster_id') AS cluster_count,
				COUNT(DISTINCT data->>'namespace') AS namespace_count,
				COUNT(*) AS container_count,
				MAX(received_at) AS last_seen
			FROM cluster_record
			WHERE data->>'kind' = 'Container'
			  AND data->>'msg' != 'DELETE'
			  AND COALESCE(data->>'digest', '') != ''
			GROUP BY data->>'registry', data->>'image', data->>'digest'
			ORDER BY container_count DESC, image
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
