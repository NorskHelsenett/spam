package scam

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
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
					AND data->>'msg' != 'DELETE'
					AND data->>'pod_phase' = 'Running') AS containers,
				COUNT(DISTINCT CONCAT(data->>'registry', '/', data->>'image', '@', data->>'digest'))
					FILTER (WHERE data->>'kind' = 'Container'
						AND data->>'msg' != 'DELETE'
						AND data->>'pod_phase' = 'Running'
						AND COALESCE(data->>'digest','') != '') AS images,
				COUNT(DISTINCT data->>'namespace')
					FILTER (WHERE data->>'kind' = 'Container'
						AND data->>'msg' != 'DELETE'
						AND data->>'pod_phase' = 'Running') AS namespaces,
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
			  AND data->>'pod_phase' = 'Running'
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
				COALESCE(data->>'digest', '') AS digest,
				STRING_AGG(DISTINCT NULLIF(data->>'tag', ''), ',') AS tags,
				COUNT(DISTINCT data->>'cluster_id') AS cluster_count,
				COUNT(DISTINCT data->>'namespace') AS namespace_count,
				COUNT(*) AS container_count,
				MAX(received_at) AS last_seen
			FROM cluster_record
			WHERE data->>'kind' = 'Container'
			  AND data->>'msg' != 'DELETE'
			  AND data->>'pod_phase' = 'Running'
			GROUP BY data->>'registry', data->>'image', data->>'digest'
			ORDER BY container_count DESC, data->>'image'
		`).Scan(&rows).Error
		if err != nil {
			http.Error(w, "query failed", http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, rows)
	}
}

// HostsHandler returns all FQDNs exposed via Ingress, HTTPRoute, and IngressRoute.
func HostsHandler(db *gorm.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		activeOnly := r.URL.Query().Get("active_only") == "true"

		type row struct {
			Host          string    `json:"host"`
			Kind          string    `json:"kind"`
			Name          string    `json:"name"`
			Namespace     string    `json:"namespace"`
			Cluster       string    `json:"cluster"`
			ClusterID     string    `json:"cluster_id"`
			Environment   string    `json:"environment"`
			TLS           bool      `json:"tls"`
			LBIPs         string    `json:"lb_ips"`
			IngressClass  string    `json:"ingress_class"`
			Backends      string    `json:"backends"`
			WorkloadCount int64     `json:"workload_count"`
			LastSeen      time.Time `json:"last_seen"`
		}
		var rows []row
		// Ingress: hosts from rules array, backends from rules[].paths[].backend_name
		// HTTPRoute/GRPCRoute/TLSRoute: hosts from hostnames array
		// IngressRoute/IngressRouteTCP: hosts from hosts array, backends from backends[].name
		err := db.Raw(`
			WITH ingress_hosts AS (
				SELECT
					r->>'host' AS host,
					data->>'kind' AS kind,
					data->>'name' AS name,
					data->>'namespace' AS namespace,
					data->>'cluster' AS cluster,
					data->>'cluster_id' AS cluster_id,
					data->>'environment' AS environment,
					jsonb_typeof(data->'tls') = 'array' AND jsonb_array_length(COALESCE(data->'tls', '[]'::jsonb)) > 0 AS tls,
					CASE WHEN jsonb_typeof(data->'lb_ips') = 'array'
						THEN COALESCE((SELECT string_agg(ip, ', ') FROM jsonb_array_elements_text(data->'lb_ips') AS ip), '')
						ELSE '' END AS lb_ips,
					COALESCE(data->>'ingress_class', '') AS ingress_class,
					CASE WHEN jsonb_typeof(r->'paths') = 'array'
						THEN COALESCE(
							(SELECT string_agg(DISTINCT p->>'backend_name', ', ')
							 FROM jsonb_array_elements(r->'paths') AS p
							 WHERE p->>'backend_name' IS NOT NULL AND p->>'backend_name' != ''),
							'')
						ELSE '' END AS backends,
					received_at AS last_seen
				FROM cluster_record
				     CROSS JOIN LATERAL jsonb_array_elements(data->'rules') AS r
				WHERE data->>'kind' = 'Ingress'
				  AND data->>'msg' != 'DELETE'
				  AND jsonb_typeof(data->'rules') = 'array'
				  AND jsonb_array_length(data->'rules') > 0
			),
			route_hosts AS (
				SELECT
					jsonb_array_elements_text(data->'hostnames') AS host,
					data->>'kind' AS kind,
					data->>'name' AS name,
					data->>'namespace' AS namespace,
					data->>'cluster' AS cluster,
					data->>'cluster_id' AS cluster_id,
					data->>'environment' AS environment,
					FALSE AS tls,
					'' AS lb_ips,
					'' AS ingress_class,
					'' AS backends,
					received_at AS last_seen
				FROM cluster_record
				WHERE data->>'kind' IN ('HTTPRoute','GRPCRoute','TLSRoute')
				  AND data->>'msg' != 'DELETE'
				  AND jsonb_typeof(data->'hostnames') = 'array'
				  AND jsonb_array_length(data->'hostnames') > 0
			),
			traefik_hosts AS (
				SELECT
					jsonb_array_elements_text(data->'hosts') AS host,
					data->>'kind' AS kind,
					data->>'name' AS name,
					data->>'namespace' AS namespace,
					data->>'cluster' AS cluster,
					data->>'cluster_id' AS cluster_id,
					data->>'environment' AS environment,
					COALESCE(data->>'tls_secret', '') != '' AS tls,
					'' AS lb_ips,
					'' AS ingress_class,
					CASE WHEN jsonb_typeof(data->'backends') = 'array'
						THEN COALESCE(
							(SELECT string_agg(DISTINCT b->>'name', ', ')
							 FROM jsonb_array_elements(data->'backends') AS b
							 WHERE b->>'name' IS NOT NULL AND b->>'name' != ''),
							'')
						ELSE '' END AS backends,
					received_at AS last_seen
				FROM cluster_record
				WHERE data->>'kind' IN ('IngressRoute','IngressRouteTCP')
				  AND data->>'msg' != 'DELETE'
				  AND jsonb_typeof(data->'hosts') = 'array'
				  AND jsonb_array_length(data->'hosts') > 0
			)
			SELECT h.host, h.kind, h.name, h.namespace, h.cluster, h.cluster_id,
			       h.environment, h.tls, h.lb_ips, h.ingress_class, h.backends,
			       COALESCE(w.cnt, 0) AS workload_count, h.last_seen
			FROM (
				SELECT * FROM ingress_hosts
				UNION ALL
				SELECT * FROM route_hosts
				UNION ALL
				SELECT * FROM traefik_hosts
			) h
			LEFT JOIN LATERAL (
				SELECT COUNT(*) AS cnt
				FROM cluster_record c
				WHERE c.data->>'kind' = 'Container'
				  AND c.data->>'msg' != 'DELETE'
				  AND c.data->>'pod_phase' = 'Running'
				  AND c.data->>'cluster_id' = h.cluster_id
				  AND c.data->>'namespace' = h.namespace
				  AND h.backends != ''
				  AND EXISTS (
				    SELECT 1 FROM cluster_record s
				    WHERE s.data->>'kind' = 'Service'
				      AND s.data->>'msg' != 'DELETE'
				      AND s.data->>'cluster_id' = h.cluster_id
				      AND s.data->>'namespace' = h.namespace
				      AND s.data->>'name' = ANY(string_to_array(h.backends, ', '))
				      AND jsonb_typeof(s.data->'selector') = 'object'
				      AND (c.data->'pod_labels') @> (s.data->'selector')
				  )
			) w ON true
			WHERE h.host IS NOT NULL AND h.host != ''
			ORDER BY h.host, h.cluster
		`).Scan(&rows).Error
		if err != nil {
			log.Printf("HostsHandler query error: %v", err)
			http.Error(w, "query failed", http.StatusInternalServerError)
			return
		}
		if activeOnly {
			filtered := rows[:0]
			for _, row := range rows {
				if row.WorkloadCount > 0 {
					filtered = append(filtered, row)
				}
			}
			rows = filtered
		}
		writeJSON(w, http.StatusOK, rows)
	}
}

// HostChainHandler returns the exposure chain for a given host: Ingress → Service(s) → Pod group(s).
func HostChainHandler(db *gorm.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		host := r.URL.Query().Get("host")
		clusterID := r.URL.Query().Get("cluster_id")
		namespace := r.URL.Query().Get("namespace")
		if host == "" || clusterID == "" || namespace == "" {
			http.Error(w, "missing host, cluster_id, or namespace", http.StatusBadRequest)
			return
		}

		type chainPath struct {
			Path        string `json:"path,omitempty"`
			BackendName string `json:"backend_name,omitempty"`
			BackendPort string `json:"backend_port,omitempty"`
		}
		type chainIngress struct {
			Kind         string      `json:"kind"`
			Name         string      `json:"name"`
			Namespace    string      `json:"namespace"`
			IngressClass string      `json:"ingress_class"`
			TLS          bool        `json:"tls"`
			LBIPs        string      `json:"lb_ips"`
			Paths        []chainPath `json:"paths"`
		}
		type chainPort struct {
			Name       string `json:"name,omitempty"`
			Port       int    `json:"port"`
			TargetPort string `json:"target_port,omitempty"`
			Protocol   string `json:"protocol,omitempty"`
		}
		type chainService struct {
			Name        string            `json:"name"`
			Namespace   string            `json:"namespace"`
			ServiceType string            `json:"service_type"`
			Ports       []chainPort       `json:"ports"`
			Selector    map[string]string `json:"selector"`
			PodCount    int64             `json:"pod_count"`
		}
		type chainContainer struct {
			Name     string `json:"name"`
			Image    string `json:"image"`
			Tag      string `json:"tag"`
			Registry string `json:"registry"`
		}
		type chainPodGroup struct {
			Owner       string           `json:"owner"`
			OwnerKind   string           `json:"owner_kind"`
			PodCount    int64            `json:"pod_count"`
			Phase       string           `json:"phase"`
			Containers  []chainContainer `json:"containers"`
			ServiceName string           `json:"service_name"`
		}
		type chainResponse struct {
			Host      string          `json:"host"`
			ClusterID string          `json:"cluster_id"`
			Namespace string          `json:"namespace"`
			Ingress   *chainIngress   `json:"ingress"`
			Services  []chainService  `json:"services"`
			Pods      []chainPodGroup `json:"pods"`
		}

		resp := chainResponse{Host: host, ClusterID: clusterID, Namespace: namespace}

		// --- Step 1: Find the ingress/route resource for this host ---
		type ingressRow struct {
			Kind         string `json:"kind"`
			Name         string `json:"name"`
			Namespace    string `json:"namespace"`
			IngressClass string `json:"ingress_class"`
			TLS          bool   `json:"tls"`
			LBIPs        string `json:"lb_ips"`
			Backends     string `json:"backends"`
			PathsJSON    string `json:"paths_json"`
		}
		var ing ingressRow
		err := db.Raw(`
			SELECT * FROM (
				-- Ingress
				SELECT
					data->>'kind' AS kind,
					data->>'name' AS name,
					data->>'namespace' AS namespace,
					COALESCE(data->>'ingress_class', '') AS ingress_class,
					jsonb_typeof(data->'tls') = 'array' AND jsonb_array_length(COALESCE(data->'tls', '[]'::jsonb)) > 0 AS tls,
					CASE WHEN jsonb_typeof(data->'lb_ips') = 'array'
						THEN COALESCE((SELECT string_agg(ip, ', ') FROM jsonb_array_elements_text(data->'lb_ips') AS ip), '')
						ELSE '' END AS lb_ips,
					COALESCE(
						(SELECT string_agg(DISTINCT p->>'backend_name', ', ')
						 FROM jsonb_array_elements(data->'rules') AS r,
						      jsonb_array_elements(r->'paths') AS p
						 WHERE r->>'host' = ?
						   AND p->>'backend_name' IS NOT NULL AND p->>'backend_name' != ''),
						'') AS backends,
					COALESCE(
						(SELECT jsonb_agg(jsonb_build_object(
							'path', p->>'path',
							'backend_name', p->>'backend_name',
							'backend_port', p->>'backend_port'))
						 FROM jsonb_array_elements(data->'rules') AS r,
						      jsonb_array_elements(r->'paths') AS p
						 WHERE r->>'host' = ?),
						'[]') AS paths_json
				FROM cluster_record
				WHERE data->>'kind' = 'Ingress'
				  AND data->>'msg' != 'DELETE'
				  AND data->>'cluster_id' = ?
				  AND data->>'namespace' = ?
				  AND jsonb_typeof(data->'rules') = 'array'
				  AND EXISTS (
				    SELECT 1 FROM jsonb_array_elements(data->'rules') AS r WHERE r->>'host' = ?
				  )
				UNION ALL
				-- IngressRoute / IngressRouteTCP
				SELECT
					data->>'kind' AS kind,
					data->>'name' AS name,
					data->>'namespace' AS namespace,
					'' AS ingress_class,
					COALESCE(data->>'tls_secret', '') != '' AS tls,
					'' AS lb_ips,
					CASE WHEN jsonb_typeof(data->'backends') = 'array'
						THEN COALESCE(
							(SELECT string_agg(DISTINCT b->>'name', ', ')
							 FROM jsonb_array_elements(data->'backends') AS b
							 WHERE b->>'name' IS NOT NULL AND b->>'name' != ''),
							'')
						ELSE '' END AS backends,
					'[]' AS paths_json
				FROM cluster_record
				WHERE data->>'kind' IN ('IngressRoute', 'IngressRouteTCP')
				  AND data->>'msg' != 'DELETE'
				  AND data->>'cluster_id' = ?
				  AND data->>'namespace' = ?
				  AND jsonb_typeof(data->'hosts') = 'array'
				  AND ? = ANY(
				    SELECT jsonb_array_elements_text(data->'hosts')
				  )
				UNION ALL
				-- HTTPRoute / GRPCRoute / TLSRoute
				SELECT
					data->>'kind' AS kind,
					data->>'name' AS name,
					data->>'namespace' AS namespace,
					'' AS ingress_class,
					FALSE AS tls,
					'' AS lb_ips,
					'' AS backends,
					'[]' AS paths_json
				FROM cluster_record
				WHERE data->>'kind' IN ('HTTPRoute', 'GRPCRoute', 'TLSRoute')
				  AND data->>'msg' != 'DELETE'
				  AND data->>'cluster_id' = ?
				  AND data->>'namespace' = ?
				  AND jsonb_typeof(data->'hostnames') = 'array'
				  AND ? = ANY(
				    SELECT jsonb_array_elements_text(data->'hostnames')
				  )
			) sub LIMIT 1
		`, host, host, clusterID, namespace, host,
			clusterID, namespace, host,
			clusterID, namespace, host,
		).Scan(&ing).Error
		if err != nil {
			log.Printf("HostChainHandler ingress query error: %v", err)
			http.Error(w, "query failed", http.StatusInternalServerError)
			return
		}
		if ing.Name != "" {
			ci := chainIngress{
				Kind: ing.Kind, Name: ing.Name, Namespace: ing.Namespace,
				IngressClass: ing.IngressClass, TLS: ing.TLS, LBIPs: ing.LBIPs,
			}
			if ing.PathsJSON != "" && ing.PathsJSON != "[]" {
				_ = json.Unmarshal([]byte(ing.PathsJSON), &ci.Paths)
			}
			resp.Ingress = &ci
		}

		// --- Step 2: Find services matching backend names ---
		backends := strings.Split(ing.Backends, ", ")
		if ing.Backends == "" {
			backends = nil
		}
		if len(backends) > 0 {
			type svcRow struct {
				Name        string `json:"name"`
				Namespace   string `json:"namespace"`
				ServiceType string `json:"service_type"`
				PortsJSON   string `json:"ports_json"`
				SelectorJSON string `json:"selector_json"`
			}
			var svcRows []svcRow
			err = db.Raw(`
				SELECT
					data->>'name' AS name,
					data->>'namespace' AS namespace,
					COALESCE(data->>'service_type', '') AS service_type,
					COALESCE(data->'ports'::text, '[]') AS ports_json,
					COALESCE(data->'selector'::text, '{}') AS selector_json
				FROM cluster_record
				WHERE data->>'kind' = 'Service'
				  AND data->>'msg' != 'DELETE'
				  AND data->>'cluster_id' = ?
				  AND data->>'namespace' = ?
				  AND data->>'name' IN (?)
			`, clusterID, namespace, backends).Scan(&svcRows).Error
			if err != nil {
				log.Printf("HostChainHandler service query error: %v", err)
			}

			for _, s := range svcRows {
				cs := chainService{
					Name: s.Name, Namespace: s.Namespace, ServiceType: s.ServiceType,
				}
				if s.PortsJSON != "" {
					_ = json.Unmarshal([]byte(s.PortsJSON), &cs.Ports)
				}
				if s.SelectorJSON != "" {
					_ = json.Unmarshal([]byte(s.SelectorJSON), &cs.Selector)
				}

				// --- Step 3: Find running pods matching this service's selector ---
				if len(cs.Selector) > 0 {
					selectorJSON, _ := json.Marshal(cs.Selector)
					type podRow struct {
						Owner      string `json:"owner"`
						OwnerKind  string `json:"owner_kind"`
						PodCount   int64  `json:"pod_count"`
						Phase      string `json:"phase"`
						Containers string `json:"containers_json"`
					}
					var podRows []podRow
					err = db.Raw(`
						SELECT
							data->>'owner' AS owner,
							data->>'owner_kind' AS owner_kind,
							COUNT(DISTINCT data->>'pod_uid') AS pod_count,
							MAX(data->>'pod_phase') AS phase,
							jsonb_agg(DISTINCT jsonb_build_object(
								'name', data->>'container',
								'image', data->>'image',
								'tag', data->>'tag',
								'registry', data->>'registry'
							)) AS containers_json
						FROM cluster_record
						WHERE data->>'kind' = 'Container'
						  AND data->>'msg' != 'DELETE'
						  AND data->>'pod_phase' = 'Running'
						  AND data->>'cluster_id' = ?
						  AND data->>'namespace' = ?
						  AND (data->'pod_labels') @> ?::jsonb
						GROUP BY data->>'owner', data->>'owner_kind'
					`, clusterID, namespace, string(selectorJSON)).Scan(&podRows).Error
					if err != nil {
						log.Printf("HostChainHandler pod query error: %v", err)
					}

					var totalPods int64
					for _, p := range podRows {
						pg := chainPodGroup{
							Owner: p.Owner, OwnerKind: p.OwnerKind,
							PodCount: p.PodCount, Phase: p.Phase,
							ServiceName: s.Name,
						}
						if p.Containers != "" {
							_ = json.Unmarshal([]byte(p.Containers), &pg.Containers)
						}
						resp.Pods = append(resp.Pods, pg)
						totalPods += p.PodCount
					}
					cs.PodCount = totalPods
				}

				resp.Services = append(resp.Services, cs)
			}
		}

		writeJSON(w, http.StatusOK, resp)
	}
}

// ResolveHostHandler does a DNS lookup for a given host and returns the IPs.
func ResolveHostHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		host := r.URL.Query().Get("host")
		if host == "" {
			http.Error(w, "missing host parameter", http.StatusBadRequest)
			return
		}

		type result struct {
			Host     string   `json:"host"`
			IPs      []string `json:"ips"`
			IsLocal  bool     `json:"is_local"`
			Error    string   `json:"error,omitempty"`
		}

		ips, err := net.LookupHost(host)
		if err != nil {
			writeJSON(w, http.StatusOK, result{Host: host, Error: "unresolvable"})
			return
		}

		local := false
		if len(ips) > 0 {
			local = isPrivateIP(ips[0])
		}

		writeJSON(w, http.StatusOK, result{Host: host, IPs: ips, IsLocal: local})
	}
}

func isPrivateIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	privateRanges := []struct{ start, end net.IP }{
		{net.ParseIP("10.0.0.0"), net.ParseIP("10.255.255.255")},
		{net.ParseIP("172.16.0.0"), net.ParseIP("172.31.255.255")},
		{net.ParseIP("192.168.0.0"), net.ParseIP("192.168.255.255")},
		{net.ParseIP("127.0.0.0"), net.ParseIP("127.255.255.255")},
	}
	for _, r := range privateRanges {
		if bytesCompare(ip.To16(), r.start.To16()) >= 0 && bytesCompare(ip.To16(), r.end.To16()) <= 0 {
			return true
		}
	}
	return false
}

func bytesCompare(a, b net.IP) int {
	for i := range a {
		if a[i] < b[i] {
			return -1
		}
		if a[i] > b[i] {
			return 1
		}
	}
	return 0
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
