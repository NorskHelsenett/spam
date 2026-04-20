package scam

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/NorskHelsenett/spam/internal/cache"
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
			// Collect distinct cluster_ids for session-touch after
			// the upsert. A batch commonly covers one cluster, but
			// support multi-cluster batches cleanly.
			clusterIDs := make(map[string]struct{}, 4)

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
					// Surface the real error so agents hitting 500s in the
					// wild can be diagnosed without re-deploying. We don't
					// echo it back to the caller (it may reveal schema
					// detail) but we do log it locally.
					log.Printf("callcenter: upsert batch failed (%d rows): %v", len(batch), err)
					http.Error(w, "database error", http.StatusInternalServerError)
					return
				}
			}

			// Re-scan items to pick up cluster_ids for the session-touch.
			// Parsed once at ingest time above via json.Unmarshal into
			// Incoming; re-parse here is wasteful but narrow. Keeps
			// the hot-path batch insert unchanged.
			for _, item := range items {
				var idOnly struct {
					ClusterID string `json:"cluster_id"`
				}
				if err := json.Unmarshal(item.data, &idOnly); err == nil && idOnly.ClusterID != "" {
					clusterIDs[idOnly.ClusterID] = struct{}{}
				}
			}
			for clusterID := range clusterIDs {
				if err := touchClusterSession(r.Context(), db, clusterID, now); err != nil {
					// Session-touch failure is non-fatal to the ingest
					// (data is already persisted). Log so it's visible
					// if it becomes chronic.
					log.Printf("callcenter: touch session %s: %v", clusterID, err)
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

// HeartbeatHandler lets agents say "still alive, no news" without
// sending data. Needed because quiet clusters can legitimately go hours
// with no state changes — under a pure-data liveness check those
// clusters would falsely go dark in the UI.
//
// Protocol: POST /api/scam/heartbeat with body {"cluster_id": "..."}.
// Extends the current session's last_push_at without rolling the
// session boundary (a heartbeat within an existing session doesn't
// clear stale state). Recommended cadence: every 60s from the agent.
//
// Unauthenticated like the callcenter endpoint — same threat model.
func HeartbeatHandler(db *gorm.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 1<<10) // 1 KiB is plenty
		var body struct {
			ClusterID string `json:"cluster_id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		if body.ClusterID == "" || len(body.ClusterID) > maxFieldLen {
			http.Error(w, "cluster_id required", http.StatusBadRequest)
			return
		}
		if err := touchClusterSession(r.Context(), db, body.ClusterID, time.Now().UTC()); err != nil {
			log.Printf("heartbeat: touch session %s: %v", body.ClusterID, err)
			http.Error(w, "database error", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

// Integrity-validation bounds. Agents are unauthenticated, so every field that
// flows into downstream SQL queries, cache keys, the HTTP client, or the image
// scanner is shape-checked here before a row is stored.
const (
	maxFieldLen    = 512
	maxHostnameLen = 253
	maxDigestLen   = 128
	maxArrayLen    = 256
)

var (
	// DNS-1123 subdomain with optional wildcard prefix (Ingress hostnames).
	hostnameRe = regexp.MustCompile(`^(\*\.)?[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$`)
	// OCI content digest — algorithm:hex, e.g. sha256:abcd...
	digestRe = regexp.MustCompile(`^[a-zA-Z0-9]+:[a-fA-F0-9]{32,}$`)
	// Container registry host — hostname[:port], no path segments.
	registryRe = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*(:[0-9]{1,5})?$`)
)

func validHostname(h string) bool {
	if h == "" || len(h) > maxHostnameLen {
		return false
	}
	// Reject IP literals — cluster topology records should only carry DNS
	// names. Storing IPs would let anonymous agents target internal or cloud
	// metadata addresses that an authenticated UI session might later fetch.
	if net.ParseIP(h) != nil {
		return false
	}
	return hostnameRe.MatchString(h)
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

	// Length caps on every free-form string that could reach SQL / cache /
	// downstream fetches. Agents are anonymous; no field should be arbitrary.
	fields := []struct {
		name, val string
	}{
		{"cluster", r.Cluster}, {"cluster_id", r.ClusterID}, {"environment", r.Environment},
		{"uid", r.UID}, {"pod_uid", r.PodUID}, {"container", r.Container},
		{"name", r.Name}, {"namespace", r.Namespace},
		{"owner", r.Owner}, {"owner_kind", r.OwnerKind},
		{"pod_phase", r.PodPhase}, {"service_type", r.ServiceType},
		{"ingress_class", r.IngressClass}, {"tls_secret", r.TLSSecret},
		{"image", r.Image}, {"tag", r.Tag},
	}
	for _, f := range fields {
		if len(f.val) > maxFieldLen {
			return fmt.Errorf("%s too long", f.name)
		}
	}

	if r.Registry != "" {
		if len(r.Registry) > maxHostnameLen+6 || !registryRe.MatchString(r.Registry) {
			return fmt.Errorf("invalid registry: %q", r.Registry)
		}
	}
	if r.Digest != "" {
		if len(r.Digest) > maxDigestLen || !digestRe.MatchString(r.Digest) {
			return fmt.Errorf("invalid digest")
		}
	}

	if len(r.Rules) > maxArrayLen || len(r.Hostnames) > maxArrayLen ||
		len(r.Hosts) > maxArrayLen || len(r.LBIPs) > maxArrayLen {
		return fmt.Errorf("array too large")
	}
	for _, rule := range r.Rules {
		if rule.Host != "" && !validHostname(rule.Host) {
			return fmt.Errorf("invalid rule host: %q", rule.Host)
		}
	}
	for _, h := range r.Hostnames {
		if !validHostname(h) {
			return fmt.Errorf("invalid hostname: %q", h)
		}
	}
	for _, h := range r.Hosts {
		if !validHostname(h) {
			return fmt.Errorf("invalid host: %q", h)
		}
	}
	for _, ip := range r.LBIPs {
		if net.ParseIP(ip) == nil {
			return fmt.Errorf("invalid lb_ip: %q", ip)
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
					AND data->>'msg' != 'DELETE' AND EXISTS (SELECT 1 FROM cluster_sessions cs WHERE cs.cluster_id = data->>'cluster_id' AND received_at >= cs.session_started_at AND cs.last_push_at >= NOW() - INTERVAL '15 minutes')
					AND data->>'pod_phase' = 'Running') AS containers,
				COUNT(DISTINCT CONCAT(data->>'registry', '/', data->>'image', '@', data->>'digest'))
					FILTER (WHERE data->>'kind' = 'Container'
						AND data->>'msg' != 'DELETE' AND EXISTS (SELECT 1 FROM cluster_sessions cs WHERE cs.cluster_id = data->>'cluster_id' AND received_at >= cs.session_started_at AND cs.last_push_at >= NOW() - INTERVAL '15 minutes')
						AND data->>'pod_phase' = 'Running'
						AND COALESCE(data->>'digest','') != '') AS images,
				COUNT(DISTINCT data->>'namespace')
					FILTER (WHERE data->>'kind' = 'Container'
						AND data->>'msg' != 'DELETE' AND EXISTS (SELECT 1 FROM cluster_sessions cs WHERE cs.cluster_id = data->>'cluster_id' AND received_at >= cs.session_started_at AND cs.last_push_at >= NOW() - INTERVAL '15 minutes')
						AND data->>'pod_phase' = 'Running') AS namespaces,
				COUNT(DISTINCT data->>'uid')
					FILTER (WHERE data->>'kind' IN ('Ingress','HTTPRoute','GRPCRoute','IngressRoute','IngressRouteTCP')
						AND data->>'msg' != 'DELETE' AND EXISTS (SELECT 1 FROM cluster_sessions cs WHERE cs.cluster_id = data->>'cluster_id' AND received_at >= cs.session_started_at AND cs.last_push_at >= NOW() - INTERVAL '15 minutes')) AS ingress_count,
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
			  AND data->>'msg' != 'DELETE' AND EXISTS (SELECT 1 FROM cluster_sessions cs WHERE cs.cluster_id = data->>'cluster_id' AND received_at >= cs.session_started_at AND cs.last_push_at >= NOW() - INTERVAL '15 minutes')
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
					  AND data->>'msg' != 'DELETE' AND EXISTS (SELECT 1 FROM cluster_sessions cs WHERE cs.cluster_id = data->>'cluster_id' AND received_at >= cs.session_started_at AND cs.last_push_at >= NOW() - INTERVAL '15 minutes')
				) AS internet_exposed,
				COUNT(DISTINCT data->>'uid') FILTER (
					WHERE data->>'kind' = 'Service'
					  AND data->>'msg' != 'DELETE' AND EXISTS (SELECT 1 FROM cluster_sessions cs WHERE cs.cluster_id = data->>'cluster_id' AND received_at >= cs.session_started_at AND cs.last_push_at >= NOW() - INTERVAL '15 minutes')
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
			DigestID       string    `json:"digest_id"` // image_digests.id — enables deep-link to /app/images/<id>
			Tags           string    `json:"tags"`      // comma-separated
			ClusterCount   int64     `json:"cluster_count"`
			NamespaceCount int64     `json:"namespace_count"`
			ContainerCount int64     `json:"container_count"`
			LastSeen       time.Time `json:"last_seen"`
		}
		var rows []row
		// Aggregate cluster observations first, then LEFT JOIN
		// image_digests so rows get a digest_id when the reconciler has
		// already harvested them (and empty otherwise — the page still
		// renders, just without a clickable link).
		err := db.Raw(`
			WITH agg AS (
			    SELECT
			        data->>'registry' AS raw_registry,
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
			      AND data->>'msg' != 'DELETE' AND EXISTS (SELECT 1 FROM cluster_sessions cs WHERE cs.cluster_id = data->>'cluster_id' AND received_at >= cs.session_started_at AND cs.last_push_at >= NOW() - INTERVAL '15 minutes')
			      AND data->>'pod_phase' = 'Running'
			    GROUP BY data->>'registry', data->>'image', data->>'digest'
			)
			SELECT
			    agg.registry, agg.image, agg.digest,
			    COALESCE(id.id, '') AS digest_id,
			    agg.tags, agg.cluster_count, agg.namespace_count,
			    agg.container_count, agg.last_seen
			FROM agg
			LEFT JOIN image_digests id
			  ON id.registry   = agg.raw_registry
			 AND id.repository = agg.image
			 AND id.digest     = agg.digest
			ORDER BY agg.container_count DESC, agg.image
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
				  AND data->>'msg' != 'DELETE' AND EXISTS (SELECT 1 FROM cluster_sessions cs WHERE cs.cluster_id = data->>'cluster_id' AND received_at >= cs.session_started_at AND cs.last_push_at >= NOW() - INTERVAL '15 minutes')
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
				  AND data->>'msg' != 'DELETE' AND EXISTS (SELECT 1 FROM cluster_sessions cs WHERE cs.cluster_id = data->>'cluster_id' AND received_at >= cs.session_started_at AND cs.last_push_at >= NOW() - INTERVAL '15 minutes')
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
				  AND data->>'msg' != 'DELETE' AND EXISTS (SELECT 1 FROM cluster_sessions cs WHERE cs.cluster_id = data->>'cluster_id' AND received_at >= cs.session_started_at AND cs.last_push_at >= NOW() - INTERVAL '15 minutes')
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
				  AND c.data->>'msg' != 'DELETE' AND EXISTS (SELECT 1 FROM cluster_sessions cs WHERE cs.cluster_id = c.data->>'cluster_id' AND c.received_at >= cs.session_started_at AND cs.last_push_at >= NOW() - INTERVAL '15 minutes')
				  AND c.data->>'pod_phase' = 'Running'
				  AND c.data->>'cluster_id' = h.cluster_id
				  AND c.data->>'namespace' = h.namespace
				  AND h.backends != ''
				  AND EXISTS (
				    SELECT 1 FROM cluster_record s
				    WHERE s.data->>'kind' = 'Service'
				      AND s.data->>'msg' != 'DELETE' AND EXISTS (SELECT 1 FROM cluster_sessions cs WHERE cs.cluster_id = s.data->>'cluster_id' AND s.received_at >= cs.session_started_at AND cs.last_push_at >= NOW() - INTERVAL '15 minutes')
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

// labelsMatch returns true if podLabels contains all key-value pairs from selector.
func labelsMatch(podLabels, selector map[string]string) bool {
	for k, v := range selector {
		if podLabels[k] != v {
			return false
		}
	}
	return true
}

// ClusterChainHandler returns the exposure chain for every namespace in a cluster.
func ClusterChainHandler(db *gorm.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		clusterID := r.URL.Query().Get("cluster_id")
		if clusterID == "" {
			http.Error(w, "missing cluster_id", http.StatusBadRequest)
			return
		}

		type nsIngress struct {
			Namespace    string `json:"namespace"`
			Host         string `json:"host"`
			Kind         string `json:"kind"`
			Name         string `json:"name"`
			IngressClass string `json:"ingress_class"`
			TLS          bool   `json:"tls"`
			Backends     string `json:"backends"`
		}
		type nsSvc struct {
			Namespace   string `json:"namespace"`
			Name        string `json:"name"`
			ServiceType string `json:"service_type"`
			PortsJSON   string `gorm:"column:ports_json"`
			SelectorJSON string `gorm:"column:selector_json"`
		}
		type nsPod struct {
			Namespace      string `json:"namespace"`
			Owner          string `json:"owner"`
			OwnerKind      string `json:"owner_kind"`
			PodCount       int64  `json:"pod_count"`
			Phase          string `json:"phase"`
			ContainersJSON string `gorm:"column:containers_json"`
			LabelsJSON     string `gorm:"column:labels_json"`
		}

		// Step 1: All ingresses/routes in this cluster
		var ingresses []nsIngress
		db.Raw(`
			SELECT * FROM (
				SELECT
					data->>'namespace' AS namespace,
					r->>'host' AS host,
					data->>'kind' AS kind,
					data->>'name' AS name,
					COALESCE(data->>'ingress_class', '') AS ingress_class,
					jsonb_typeof(data->'tls') = 'array' AND jsonb_array_length(COALESCE(data->'tls', '[]'::jsonb)) > 0 AS tls,
					COALESCE(
						(SELECT string_agg(DISTINCT p->>'backend_name', ', ')
						 FROM jsonb_array_elements(r->'paths') AS p
						 WHERE p->>'backend_name' IS NOT NULL AND p->>'backend_name' != ''),
						'') AS backends
				FROM cluster_record
				     CROSS JOIN LATERAL jsonb_array_elements(data->'rules') AS r
				WHERE data->>'kind' = 'Ingress'
				  AND data->>'msg' != 'DELETE' AND EXISTS (SELECT 1 FROM cluster_sessions cs WHERE cs.cluster_id = data->>'cluster_id' AND received_at >= cs.session_started_at AND cs.last_push_at >= NOW() - INTERVAL '15 minutes')
				  AND data->>'cluster_id' = ?
				  AND jsonb_typeof(data->'rules') = 'array'
				UNION ALL
				SELECT
					data->>'namespace' AS namespace,
					h AS host,
					data->>'kind' AS kind,
					data->>'name' AS name,
					'' AS ingress_class,
					COALESCE(data->>'tls_secret', '') != '' AS tls,
					CASE WHEN jsonb_typeof(data->'backends') = 'array'
						THEN COALESCE(
							(SELECT string_agg(DISTINCT b->>'name', ', ')
							 FROM jsonb_array_elements(data->'backends') AS b), '')
						ELSE '' END AS backends
				FROM cluster_record,
				     jsonb_array_elements_text(data->'hosts') AS h
				WHERE data->>'kind' IN ('IngressRoute','IngressRouteTCP')
				  AND data->>'msg' != 'DELETE' AND EXISTS (SELECT 1 FROM cluster_sessions cs WHERE cs.cluster_id = data->>'cluster_id' AND received_at >= cs.session_started_at AND cs.last_push_at >= NOW() - INTERVAL '15 minutes')
				  AND data->>'cluster_id' = ?
				  AND jsonb_typeof(data->'hosts') = 'array'
				UNION ALL
				SELECT
					data->>'namespace' AS namespace,
					h AS host,
					data->>'kind' AS kind,
					data->>'name' AS name,
					'' AS ingress_class,
					FALSE AS tls,
					'' AS backends
				FROM cluster_record,
				     jsonb_array_elements_text(data->'hostnames') AS h
				WHERE data->>'kind' IN ('HTTPRoute','GRPCRoute','TLSRoute')
				  AND data->>'msg' != 'DELETE' AND EXISTS (SELECT 1 FROM cluster_sessions cs WHERE cs.cluster_id = data->>'cluster_id' AND received_at >= cs.session_started_at AND cs.last_push_at >= NOW() - INTERVAL '15 minutes')
				  AND data->>'cluster_id' = ?
				  AND jsonb_typeof(data->'hostnames') = 'array'
			) sub WHERE host IS NOT NULL AND host != ''
			ORDER BY namespace, host
		`, clusterID, clusterID, clusterID).Scan(&ingresses)

		// Step 2: All services in this cluster
		var services []nsSvc
		db.Raw(`
			SELECT
				data->>'namespace' AS namespace,
				data->>'name' AS name,
				COALESCE(data->>'service_type', '') AS service_type,
				COALESCE(data->'ports'::text, '[]') AS ports_json,
				COALESCE(data->'selector'::text, '{}') AS selector_json
			FROM cluster_record
			WHERE data->>'kind' = 'Service'
			  AND data->>'msg' != 'DELETE' AND EXISTS (SELECT 1 FROM cluster_sessions cs WHERE cs.cluster_id = data->>'cluster_id' AND received_at >= cs.session_started_at AND cs.last_push_at >= NOW() - INTERVAL '15 minutes')
			  AND data->>'cluster_id' = ?
			ORDER BY data->>'namespace', data->>'name'
		`, clusterID).Scan(&services)

		// Step 3: All running pod groups in this cluster
		var pods []nsPod
		db.Raw(`
			SELECT
				data->>'namespace' AS namespace,
				data->>'owner' AS owner,
				data->>'owner_kind' AS owner_kind,
				COUNT(DISTINCT data->>'pod_uid') AS pod_count,
				MAX(data->>'pod_phase') AS phase,
				jsonb_agg(DISTINCT jsonb_build_object(
					'name', data->>'container',
					'image', data->>'image',
					'tag', data->>'tag',
					'digest', data->>'digest',
					'registry', data->>'registry'
				)) AS containers_json,
				(array_agg(data->'pod_labels'))[1] AS labels_json
			FROM cluster_record
			WHERE data->>'kind' = 'Container'
			  AND data->>'msg' != 'DELETE' AND EXISTS (SELECT 1 FROM cluster_sessions cs WHERE cs.cluster_id = data->>'cluster_id' AND received_at >= cs.session_started_at AND cs.last_push_at >= NOW() - INTERVAL '15 minutes')
			  AND data->>'pod_phase' = 'Running'
			  AND data->>'cluster_id' = ?
			GROUP BY data->>'namespace', data->>'owner', data->>'owner_kind'
			ORDER BY data->>'namespace', data->>'owner'
		`, clusterID).Scan(&pods)

		// Build per-namespace view
		type chainContainer struct {
			Name     string `json:"name"`
			Image    string `json:"image"`
			Tag      string `json:"tag"`
			Digest   string `json:"digest,omitempty"`
			Registry string `json:"registry"`
		}
		type chainPodGroup struct {
			Owner        string           `json:"owner"`
			OwnerKind    string           `json:"owner_kind"`
			PodCount     int64            `json:"pod_count"`
			Phase        string           `json:"phase"`
			Containers   []chainContainer `json:"containers"`
			ServiceNames []string         `json:"service_names"`
			// Transient marks pod groups that aren't currently Running but
			// have been observed in the cluster recently (e.g. CronJob-spawned
			// pods that finished, failed, or were evicted). UI renders these
			// muted so operators see the recent-but-ephemeral workloads
			// without losing focus on what's live.
			Transient bool      `json:"transient,omitempty"`
			LastSeen  time.Time `json:"last_seen,omitempty"`
		}
		type chainSvc struct {
			Name        string            `json:"name"`
			ServiceType string            `json:"service_type"`
			Ports       json.RawMessage   `json:"ports"`
			Selector    map[string]string `json:"selector"`
		}
		type chainIng struct {
			Host         string `json:"host"`
			Kind         string `json:"kind"`
			Name         string `json:"name"`
			IngressClass string `json:"ingress_class"`
			TLS          bool   `json:"tls"`
			Backends     string `json:"backends"`
		}
		type nsChain struct {
			Namespace string         `json:"namespace"`
			Ingresses []chainIng     `json:"ingresses"`
			Services  []chainSvc     `json:"services"`
			Pods      []chainPodGroup `json:"pods"`
		}

		nsMap := map[string]*nsChain{}
		getOrCreate := func(ns string) *nsChain {
			if c, ok := nsMap[ns]; ok {
				return c
			}
			c := &nsChain{Namespace: ns}
			nsMap[ns] = c
			return c
		}

		for _, ing := range ingresses {
			c := getOrCreate(ing.Namespace)
			c.Ingresses = append(c.Ingresses, chainIng{
				Host: ing.Host, Kind: ing.Kind, Name: ing.Name,
				IngressClass: ing.IngressClass, TLS: ing.TLS, Backends: ing.Backends,
			})
		}
		for _, svc := range services {
			c := getOrCreate(svc.Namespace)
			cs := chainSvc{Name: svc.Name, ServiceType: svc.ServiceType}
			if svc.PortsJSON != "" {
				cs.Ports = json.RawMessage(svc.PortsJSON)
			}
			if svc.SelectorJSON != "" {
				_ = json.Unmarshal([]byte(svc.SelectorJSON), &cs.Selector)
			}
			c.Services = append(c.Services, cs)
		}
		for _, pod := range pods {
			c := getOrCreate(pod.Namespace)
			pg := chainPodGroup{
				Owner: pod.Owner, OwnerKind: pod.OwnerKind,
				PodCount: pod.PodCount, Phase: pod.Phase,
			}
			if pod.ContainersJSON != "" {
				_ = json.Unmarshal([]byte(pod.ContainersJSON), &pg.Containers)
			}
			// Match this pod group to ALL services whose selectors match
			if pod.LabelsJSON != "" {
				var podLabels map[string]string
				if json.Unmarshal([]byte(pod.LabelsJSON), &podLabels) == nil {
					for _, svc := range c.Services {
						if len(svc.Selector) > 0 && labelsMatch(podLabels, svc.Selector) {
							pg.ServiceNames = append(pg.ServiceNames, svc.Name)
						}
					}
				}
			}
			c.Pods = append(c.Pods, pg)
		}

		// Step 3b: Transient pod groups — non-Running container observations
		// from the last 24h. Excludes owners we already rendered above (the
		// Running row is authoritative) so we don't double-list a deployment
		// that happens to have one crashed pod alongside healthy ones.
		type transientPodRow struct {
			Namespace      string    `gorm:"column:namespace"`
			Owner          string    `gorm:"column:owner"`
			OwnerKind      string    `gorm:"column:owner_kind"`
			PodCount       int64     `gorm:"column:pod_count"`
			Phase          string    `gorm:"column:phase"`
			ContainersJSON string    `gorm:"column:containers_json"`
			LastSeen       time.Time `gorm:"column:last_seen"`
		}
		var transientPods []transientPodRow
		db.Raw(`
			SELECT
				data->>'namespace' AS namespace,
				data->>'owner' AS owner,
				data->>'owner_kind' AS owner_kind,
				COUNT(DISTINCT data->>'pod_uid') AS pod_count,
				(array_agg(data->>'pod_phase' ORDER BY received_at DESC))[1] AS phase,
				jsonb_agg(DISTINCT jsonb_build_object(
					'name', data->>'container',
					'image', data->>'image',
					'tag', data->>'tag',
					'digest', data->>'digest',
					'registry', data->>'registry'
				)) AS containers_json,
				MAX(received_at) AS last_seen
			FROM cluster_record
			WHERE data->>'kind' = 'Container'
			  AND data->>'msg' != 'DELETE'
			  AND (data->>'pod_phase' IS NULL OR data->>'pod_phase' != 'Running')
			  AND data->>'cluster_id' = ?
			  -- Transient query intentionally spans the last 24h so
			  -- recently-completed Jobs surface in the chain drawer,
			  -- even after the current agent session boundary.
			  AND received_at >= NOW() - INTERVAL '24 hours'
			GROUP BY data->>'namespace', data->>'owner', data->>'owner_kind'
			ORDER BY data->>'namespace', data->>'owner'
		`, clusterID).Scan(&transientPods)

		// De-dupe against the Running set — an owner that already appears in
		// pg (Running) shouldn't also render as transient.
		liveKeys := make(map[string]struct{}, len(pods))
		for _, p := range pods {
			liveKeys[p.Namespace+"/"+p.Owner+"/"+p.OwnerKind] = struct{}{}
		}
		for _, pod := range transientPods {
			if _, dup := liveKeys[pod.Namespace+"/"+pod.Owner+"/"+pod.OwnerKind]; dup {
				continue
			}
			c := getOrCreate(pod.Namespace)
			pg := chainPodGroup{
				Owner: pod.Owner, OwnerKind: pod.OwnerKind,
				PodCount: pod.PodCount, Phase: pod.Phase,
				Transient: true, LastSeen: pod.LastSeen,
			}
			if pod.ContainersJSON != "" {
				_ = json.Unmarshal([]byte(pod.ContainersJSON), &pg.Containers)
			}
			c.Pods = append(c.Pods, pg)
		}

		// Look up cluster name
		var clusterName string
		db.Raw(`SELECT data->>'cluster' FROM cluster_record WHERE data->>'cluster_id' = ? AND data->>'cluster' IS NOT NULL AND data->>'cluster' != '' LIMIT 1`, clusterID).Scan(&clusterName)

		// Sort namespaces and build result
		type result struct {
			Cluster    string    `json:"cluster"`
			ClusterID  string    `json:"cluster_id"`
			Namespaces []nsChain `json:"namespaces"`
		}
		res := result{Cluster: clusterName, ClusterID: clusterID}
		// Collect and sort namespace names
		nsNames := make([]string, 0, len(nsMap))
		for ns := range nsMap {
			nsNames = append(nsNames, ns)
		}
		sort.Strings(nsNames)
		for _, ns := range nsNames {
			res.Namespaces = append(res.Namespaces, *nsMap[ns])
		}

		writeJSON(w, http.StatusOK, res)
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
			Digest   string `json:"digest,omitempty"`
			Registry string `json:"registry"`
		}
		type chainPodGroup struct {
			Owner        string           `json:"owner"`
			OwnerKind    string           `json:"owner_kind"`
			PodCount     int64            `json:"pod_count"`
			Phase        string           `json:"phase"`
			Containers   []chainContainer `json:"containers"`
			ServiceName  string           `json:"service_name"`
		}
		type chainResponse struct {
			Host      string          `json:"host"`
			Cluster   string          `json:"cluster"`
			ClusterID string          `json:"cluster_id"`
			Namespace string          `json:"namespace"`
			Ingress   *chainIngress   `json:"ingress"`
			Services  []chainService  `json:"services"`
			Pods      []chainPodGroup `json:"pods"`
		}

		// Look up cluster name from any record with this cluster_id.
		var clusterName string
		db.Raw(`SELECT data->>'cluster' FROM cluster_record WHERE data->>'cluster_id' = ? AND data->>'cluster' IS NOT NULL AND data->>'cluster' != '' LIMIT 1`, clusterID).Scan(&clusterName)

		resp := chainResponse{Host: host, Cluster: clusterName, ClusterID: clusterID, Namespace: namespace}

		// --- Step 1: Find the ingress/route resource for this host ---
		type ingressRow struct {
			Kind         string `json:"kind"`
			Name         string `json:"name"`
			Namespace    string `json:"namespace"`
			IngressClass string `json:"ingress_class"`
			TLS          bool   `json:"tls"`
			LBIPs        string `json:"lb_ips"`
			Backends     string `json:"backends"`
			PathsJSON    string `gorm:"column:paths_json"`
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
				  AND data->>'msg' != 'DELETE' AND EXISTS (SELECT 1 FROM cluster_sessions cs WHERE cs.cluster_id = data->>'cluster_id' AND received_at >= cs.session_started_at AND cs.last_push_at >= NOW() - INTERVAL '15 minutes')
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
				  AND data->>'msg' != 'DELETE' AND EXISTS (SELECT 1 FROM cluster_sessions cs WHERE cs.cluster_id = data->>'cluster_id' AND received_at >= cs.session_started_at AND cs.last_push_at >= NOW() - INTERVAL '15 minutes')
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
				  AND data->>'msg' != 'DELETE' AND EXISTS (SELECT 1 FROM cluster_sessions cs WHERE cs.cluster_id = data->>'cluster_id' AND received_at >= cs.session_started_at AND cs.last_push_at >= NOW() - INTERVAL '15 minutes')
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
				PortsJSON    string `gorm:"column:ports_json"`
				SelectorJSON string `gorm:"column:selector_json"`
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
				  AND data->>'msg' != 'DELETE' AND EXISTS (SELECT 1 FROM cluster_sessions cs WHERE cs.cluster_id = data->>'cluster_id' AND received_at >= cs.session_started_at AND cs.last_push_at >= NOW() - INTERVAL '15 minutes')
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
						Containers string `gorm:"column:containers_json"`
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
								'digest', data->>'digest',
								'registry', data->>'registry'
							)) AS containers_json
						FROM cluster_record
						WHERE data->>'kind' = 'Container'
						  AND data->>'msg' != 'DELETE' AND EXISTS (SELECT 1 FROM cluster_sessions cs WHERE cs.cluster_id = data->>'cluster_id' AND received_at >= cs.session_started_at AND cs.last_push_at >= NOW() - INTERVAL '15 minutes')
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
func ResolveHostHandler(cs cache.Store) http.HandlerFunc {
	const resolveTTL = 1 * time.Hour
	const resolvePrefix = "resolve:"

	type result struct {
		Host    string   `json:"host"`
		IPs     []string `json:"ips"`
		IsLocal bool     `json:"is_local"`
		Error   string   `json:"error,omitempty"`
	}

	return func(w http.ResponseWriter, r *http.Request) {
		host := r.URL.Query().Get("host")
		if host == "" {
			http.Error(w, "missing host parameter", http.StatusBadRequest)
			return
		}

		ctx := r.Context()
		cacheKey := resolvePrefix + host

		if cached, ok, _ := cache.GetJSON[result](ctx, cs, cacheKey); ok {
			writeJSON(w, http.StatusOK, cached)
			return
		}

		ips, err := net.LookupHost(host)
		if err != nil {
			res := result{Host: host, Error: "unresolvable"}
			_ = cache.SetJSON(ctx, cs, cacheKey, res, resolveTTL)
			writeJSON(w, http.StatusOK, res)
			return
		}

		local := false
		if len(ips) > 0 {
			local = isPrivateIP(ips[0])
		}

		res := result{Host: host, IPs: ips, IsLocal: local}
		_ = cache.SetJSON(ctx, cs, cacheKey, res, resolveTTL)
		writeJSON(w, http.StatusOK, res)
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
