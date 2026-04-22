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
// resource identity from the JSONB data column. Matches ux_cluster_record_resource.
//
// One row per resource: an INITIAL followed by UPDATE / DELETE for the
// same resource updates the single row in place (replacing `data` + bumping
// received_at) rather than creating a lifecycle log. The `msg` column still
// reflects the most recent event so queries can filter out DELETEd rows.
const resourceKeyExpr = `(
	(data->>'cluster_id') || ':' || (data->>'kind') || ':' ||
	CASE WHEN data->>'kind' = 'Container'
	     THEN (data->>'pod_uid') || '/' || (data->>'container')
	     ELSE COALESCE(data->>'uid', '')
	END
)`

// liveCTE deduplicates cluster_record rows to one-per-resource-identity
// AND restricts to currently-live clusters. Combined:
//
//	- DISTINCT ON takes the latest non-DELETE row per resource (belt-
//	  and-braces against any residual msg-duplication; the
//	  20260420_dedupe_cluster_record_msg migration plus the resource-
//	  keyed unique index normally guarantee this).
//	- Join to cluster_sessions filters out silent clusters whose
//	  agent hasn't heartbeated within sessionLiveWindow. Heartbeats
//	  and data pushes both bump last_push_at, so a quiet-but-alive
//	  cluster stays visible. We deliberately don't gate on
//	  session_started_at — agent reconnects shouldn't wipe prior
//	  resources, since the agent doesn't reliably re-INITIAL.
//
// Every live-state query reads FROM live and gets both behaviours
// for free — no per-query session-filter boilerplate.
var liveCTE = `WITH live AS (
	SELECT DISTINCT ON (
		cr.data->>'cluster_id',
		CASE WHEN cr.data->>'kind' = 'Container'
		     THEN 'Container:' || (cr.data->>'pod_uid') || '/' || (cr.data->>'container')
		     ELSE (cr.data->>'kind') || ':' || COALESCE(cr.data->>'uid', '')
		END
	) cr.*
	FROM cluster_record cr
	JOIN cluster_sessions cs ON cs.cluster_id = cr.data->>'cluster_id'
	WHERE cr.data->>'msg' != 'DELETE'
	  AND cs.last_push_at >= NOW() - ` + liveWindowInterval() + `
	ORDER BY cr.data->>'cluster_id',
		CASE WHEN cr.data->>'kind' = 'Container'
		     THEN 'Container:' || (cr.data->>'pod_uid') || '/' || (cr.data->>'container')
		     ELSE (cr.data->>'kind') || ':' || COALESCE(cr.data->>'uid', '')
		END,
		cr.received_at DESC
) `

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
		var rejected int

		// Dedupe by upsert key WITHIN the batch. Postgres disallows a
		// single INSERT … ON CONFLICT DO UPDATE affecting the same row
		// twice (SQLSTATE 21000), so a batch containing both an INITIAL
		// and a later UPDATE for the same resource must collapse to the
		// last one before we build the VALUES list. Last wins, which
		// matches "most recent state".
		keyed := make(map[string]upsertItem)
		order := make([]string, 0, len(raw))
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
			key := incoming.ClusterID + ":" + incoming.Kind + ":"
			if incoming.Kind == "Container" {
				key += incoming.PodUID + "/" + incoming.Container
			} else {
				key += incoming.UID
			}
			if _, seen := keyed[key]; !seen {
				order = append(order, key)
			}
			keyed[key] = upsertItem{data: datatypes.JSON(item)}
		}
		items := make([]upsertItem, 0, len(keyed))
		for _, key := range order {
			items = append(items, keyed[key])
		}

		if len(items) > 0 {
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
					// Surface the underlying GORM error so silent 500s
					// become diagnosable without a re-deploy.
					log.Printf("callcenter: upsert batch failed (%d rows): %v", len(batch), err)
					http.Error(w, "database error", http.StatusInternalServerError)
					return
				}
			}

			// Touch cluster_sessions so every live-state query can see
			// the current session boundary. Re-scan items for cluster_ids;
			// cheap given typical batch sizes.
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
// session boundary. Recommended cadence: every 60s from the agent.
//
// Unauthenticated like the callcenter endpoint — same threat model.
func HeartbeatHandler(db *gorm.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 1<<10)
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
	hostnameRe = regexp.MustCompile(`^(\*\.)?[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$`)
	digestRe   = regexp.MustCompile(`^[a-zA-Z0-9]+:[a-fA-F0-9]{32,}$`)
	registryRe = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*(:[0-9]{1,5})?$`)
)

func validHostname(h string) bool {
	if h == "" || len(h) > maxHostnameLen {
		return false
	}
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
		rows := []row{}
		err := db.Raw(liveCTE + `
			SELECT
				data->>'cluster'     AS cluster,
				data->>'cluster_id'  AS cluster_id,
				data->>'environment' AS environment,
				COUNT(*) FILTER (WHERE data->>'kind' = 'Container'
					AND data->>'pod_phase' = 'Running') AS containers,
				COUNT(DISTINCT CONCAT(data->>'registry', '/', data->>'image', '@', data->>'digest'))
					FILTER (WHERE data->>'kind' = 'Container'
						AND data->>'pod_phase' = 'Running'
						AND COALESCE(data->>'digest','') != '') AS images,
				COUNT(DISTINCT data->>'namespace')
					FILTER (WHERE data->>'kind' = 'Container'
						AND data->>'pod_phase' = 'Running') AS namespaces,
				COUNT(DISTINCT data->>'uid')
					FILTER (WHERE data->>'kind' IN ('Ingress','HTTPRoute','GRPCRoute','IngressRoute','IngressRouteTCP')) AS ingress_count,
				MAX(received_at) AS last_seen
			FROM live
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
		rows := []row{}
		err := db.Raw(liveCTE + `
			SELECT
				COALESCE(NULLIF(data->>'registry', ''), 'Docker Hub') AS registry,
				COUNT(DISTINCT CONCAT(data->>'registry', '/', data->>'image', '@', data->>'digest')) AS image_count
			FROM live
			WHERE data->>'kind' = 'Container'
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
		err := db.Raw(liveCTE + `
			SELECT
				COUNT(DISTINCT data->>'uid') FILTER (
					WHERE data->>'kind' IN ('Ingress','HTTPRoute','GRPCRoute','IngressRoute','IngressRouteTCP')
				) AS internet_exposed,
				COUNT(DISTINCT data->>'uid') FILTER (
					WHERE data->>'kind' = 'Service'
				) AS internal_services
			FROM live
		`).Scan(&res).Error
		if err != nil {
			http.Error(w, "query failed", http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, res)
	}
}

// ImageDetailHandler returns images grouped by registry/image/digest with
// tags, plus a digest_id (from image_digests) for drawer deep-linking
// and severity counts from the latest SUCCEEDED IMAGE_SCAN for that
// digest.
func ImageDetailHandler(db *gorm.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		type row struct {
			Registry       string    `json:"registry"`
			Image          string    `json:"image"`
			Digest         string    `json:"digest"`
			DigestID       string    `json:"digest_id"` // image_digests.id — enables the drawer row-click
			Tags           string    `json:"tags"`      // comma-separated
			ClusterCount   int64     `json:"cluster_count"`
			NamespaceCount int64     `json:"namespace_count"`
			ContainerCount int64     `json:"container_count"`
			LastSeen       time.Time `json:"last_seen"`
			VulnCritical   int       `json:"vuln_critical"`
			VulnHigh       int       `json:"vuln_high"`
			VulnMedium     int       `json:"vuln_medium"`
			VulnLow        int       `json:"vuln_low"`
			VulnUnknown    int       `json:"vuln_unknown"`
		}
		rows := []row{}
		err := db.Raw(liveCTE + `,
			agg AS (
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
				FROM live
				WHERE data->>'kind' = 'Container'
				  AND data->>'pod_phase' = 'Running'
				GROUP BY data->>'registry', data->>'image', data->>'digest'
			),
			latest_scan AS (
				SELECT DISTINCT ON (payload->>'image_digest_id')
				       payload->>'image_digest_id' AS image_digest_id,
				       id AS scan_run_id
				FROM jobs
				WHERE type = 'IMAGE_SCAN' AND status = 'SUCCEEDED'
				ORDER BY payload->>'image_digest_id', created_at DESC
			),
			vuln_counts AS (
				-- Qualify image_digest_id with f. — both tables expose it
				-- after the JOIN; unqualified references are ambiguous.
				SELECT f.image_digest_id,
				    COUNT(*) FILTER (WHERE UPPER(severity) = 'CRITICAL')            AS vuln_critical,
				    COUNT(*) FILTER (WHERE UPPER(severity) = 'HIGH')                AS vuln_high,
				    COUNT(*) FILTER (WHERE UPPER(severity) = 'MEDIUM')              AS vuln_medium,
				    COUNT(*) FILTER (WHERE UPPER(severity) IN ('LOW','NEGLIGIBLE')) AS vuln_low,
				    COUNT(*) FILTER (WHERE UPPER(severity) NOT IN ('CRITICAL','HIGH','MEDIUM','LOW','NEGLIGIBLE')) AS vuln_unknown
				FROM image_vuln_findings f
				JOIN latest_scan ls ON ls.scan_run_id = f.scan_run_id
				GROUP BY f.image_digest_id
			)
			SELECT
				agg.registry, agg.image, agg.digest,
				COALESCE(id.id, '') AS digest_id,
				agg.tags, agg.cluster_count, agg.namespace_count,
				agg.container_count, agg.last_seen,
				COALESCE(vc.vuln_critical, 0) AS vuln_critical,
				COALESCE(vc.vuln_high, 0)     AS vuln_high,
				COALESCE(vc.vuln_medium, 0)   AS vuln_medium,
				COALESCE(vc.vuln_low, 0)      AS vuln_low,
				COALESCE(vc.vuln_unknown, 0)  AS vuln_unknown
			FROM agg
			LEFT JOIN image_digests id
			  ON id.registry   = agg.raw_registry
			 AND id.repository = agg.image
			 AND id.digest     = agg.digest
			LEFT JOIN vuln_counts vc ON vc.image_digest_id = id.id
			ORDER BY agg.container_count DESC, agg.image
		`).Scan(&rows).Error
		if err != nil {
			log.Printf("clusters/images/detail: %v", err)
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
		rows := []row{}
		// Ingress: hosts from rules array, backends from rules[].paths[].backend_name
		// HTTPRoute/GRPCRoute/TLSRoute: hosts from hostnames array
		// IngressRoute/IngressRouteTCP: hosts from hosts array, backends from backends[].name
		err := db.Raw(liveCTE + `,
			ingress_hosts AS (
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
				FROM live
				     CROSS JOIN LATERAL jsonb_array_elements(data->'rules') AS r
				WHERE data->>'kind' = 'Ingress'
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
				FROM live
				WHERE data->>'kind' IN ('HTTPRoute','GRPCRoute','TLSRoute')
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
				FROM live
				WHERE data->>'kind' IN ('IngressRoute','IngressRouteTCP')
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
				FROM live c
				WHERE c.data->>'kind' = 'Container'
				  AND c.data->>'pod_phase' = 'Running'
				  AND c.data->>'cluster_id' = h.cluster_id
				  AND c.data->>'namespace' = h.namespace
				  AND h.backends != ''
				  AND EXISTS (
				    SELECT 1 FROM live s
				    WHERE s.data->>'kind' = 'Service'
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
		db.Raw(liveCTE + `
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
				FROM live
				     CROSS JOIN LATERAL jsonb_array_elements(data->'rules') AS r
				WHERE data->>'kind' = 'Ingress'
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
				FROM live,
				     jsonb_array_elements_text(data->'hosts') AS h
				WHERE data->>'kind' IN ('IngressRoute','IngressRouteTCP')
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
				FROM live,
				     jsonb_array_elements_text(data->'hostnames') AS h
				WHERE data->>'kind' IN ('HTTPRoute','GRPCRoute','TLSRoute')
				  AND data->>'cluster_id' = ?
				  AND jsonb_typeof(data->'hostnames') = 'array'
			) sub WHERE host IS NOT NULL AND host != ''
			ORDER BY namespace, host
		`, clusterID, clusterID, clusterID).Scan(&ingresses)

		// Step 2: All services in this cluster
		var services []nsSvc
		db.Raw(liveCTE + `
			SELECT
				data->>'namespace' AS namespace,
				data->>'name' AS name,
				COALESCE(data->>'service_type', '') AS service_type,
				COALESCE(data->'ports'::text, '[]') AS ports_json,
				COALESCE(data->'selector'::text, '{}') AS selector_json
			FROM live
			WHERE data->>'kind' = 'Service'
			  AND data->>'cluster_id' = ?
			ORDER BY data->>'namespace', data->>'name'
		`, clusterID).Scan(&services)

		// Step 3: All running pod groups in this cluster
		var pods []nsPod
		db.Raw(liveCTE + `
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
			FROM live
			WHERE data->>'kind' = 'Container'
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
			// have been observed in the cluster recently (Pending Jobs,
			// Succeeded/Failed CronJob firings, crashed replicas). UI
			// renders these muted so operators see what's happening in the
			// cluster without losing focus on live work.
			Transient bool      `json:"transient,omitempty"`
			LastSeen  time.Time `json:"last_seen,omitempty"`
		}
		type chainSvc struct {
			Name          string            `json:"name"`
			ServiceType   string            `json:"service_type"`
			Ports         json.RawMessage   `json:"ports"`
			Selector      map[string]string `json:"selector"`
			EndpointIPs   []string          `json:"endpoint_ips,omitempty"`
			EndpointPorts []int             `json:"endpoint_ports,omitempty"`
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

		// Transient pod groups — non-Running containers observed in the
		// last 24h. Excludes owners already rendered above (Running row
		// is authoritative). Bypasses the session-filtered `live` CTE on
		// purpose: we want to surface recently-completed Jobs even after
		// the current agent session's boundary, so operators see what
		// happened in the cluster, not only what's alive this minute.
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
			  AND received_at >= NOW() - INTERVAL '24 hours'
			GROUP BY data->>'namespace', data->>'owner', data->>'owner_kind'
			ORDER BY data->>'namespace', data->>'owner'
		`, clusterID).Scan(&transientPods)

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

		// Populate EndpointSlice IPs for services that have no matching pods
		type epIPRow struct {
			Namespace   string `json:"namespace"`
			ServiceName string `gorm:"column:service_name"`
			Address     string `gorm:"column:address"`
		}
		var epIPs []epIPRow
		db.Raw(liveCTE + `
			SELECT
				data->>'namespace' AS namespace,
				data->>'service_name' AS service_name,
				jsonb_array_elements_text(
					jsonb_array_elements(data->'endpoints')->'addresses'
				) AS address
			FROM live
			WHERE data->>'kind' = 'EndpointSlice'
			  AND data->>'cluster_id' = ?
		`, clusterID).Scan(&epIPs)

		// Endpoint ports per service
		type epPortRow struct {
			Namespace   string `json:"namespace"`
			ServiceName string `gorm:"column:service_name"`
			Port        int    `gorm:"column:port"`
		}
		var epPortRows []epPortRow
		db.Raw(liveCTE + `
			SELECT DISTINCT
				data->>'namespace' AS namespace,
				data->>'service_name' AS service_name,
				(p->>'port')::int AS port
			FROM live, jsonb_array_elements(data->'ports') AS p
			WHERE data->>'kind' = 'EndpointSlice'
			  AND data->>'cluster_id' = ?
			  AND p->>'port' IS NOT NULL
		`, clusterID).Scan(&epPortRows)

		// Build maps: namespace/service_name → IPs and ports
		epMap := make(map[string][]string)
		for _, ep := range epIPs {
			key := ep.Namespace + "/" + ep.ServiceName
			if ep.Address != "" {
				epMap[key] = append(epMap[key], ep.Address)
			}
		}
		epPortMap := make(map[string][]int)
		for _, ep := range epPortRows {
			key := ep.Namespace + "/" + ep.ServiceName
			epPortMap[key] = append(epPortMap[key], ep.Port)
		}

		// Attach endpoint IPs and ports to services that have no pods connected
		for ns, chain := range nsMap {
			connectedSvcs := make(map[string]bool)
			for _, pg := range chain.Pods {
				for _, sn := range pg.ServiceNames {
					connectedSvcs[sn] = true
				}
			}
			for i, svc := range chain.Services {
				if !connectedSvcs[svc.Name] {
					key := ns + "/" + svc.Name
					if ips, ok := epMap[key]; ok {
						chain.Services[i].EndpointIPs = ips
					}
					if ports, ok := epPortMap[key]; ok {
						chain.Services[i].EndpointPorts = ports
					}
				}
			}
		}

		// Look up cluster name
		var clusterName string
		db.Raw(liveCTE+`SELECT data->>'cluster' FROM live WHERE data->>'cluster_id' = ? AND data->>'cluster' IS NOT NULL AND data->>'cluster' != '' LIMIT 1`, clusterID).Scan(&clusterName)

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
			EndpointIPs   []string `json:"endpoint_ips,omitempty"`
			EndpointPorts []int    `json:"endpoint_ports,omitempty"`
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
		db.Raw(liveCTE+`SELECT data->>'cluster' FROM live WHERE data->>'cluster_id' = ? AND data->>'cluster' IS NOT NULL AND data->>'cluster' != '' LIMIT 1`, clusterID).Scan(&clusterName)

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
		err := db.Raw(liveCTE + `
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
				FROM live
				WHERE data->>'kind' = 'Ingress'
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
				FROM live
				WHERE data->>'kind' IN ('IngressRoute', 'IngressRouteTCP')
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
				FROM live
				WHERE data->>'kind' IN ('HTTPRoute', 'GRPCRoute', 'TLSRoute')
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
			err = db.Raw(liveCTE+`
				SELECT
					data->>'name' AS name,
					data->>'namespace' AS namespace,
					COALESCE(data->>'service_type', '') AS service_type,
					COALESCE(data->'ports'::text, '[]') AS ports_json,
					COALESCE(data->'selector'::text, '{}') AS selector_json
				FROM live
				WHERE data->>'kind' = 'Service'
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
					err = db.Raw(liveCTE+`
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
						FROM live
						WHERE data->>'kind' = 'Container'
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

		// --- Step 4: Find additional services that select the same pods ---
		// This picks up sibling services like gitea-ssh (LoadBalancer) that
		// share the same pod selector as the ingress-backed gitea-http.
		if len(resp.Pods) > 0 {
			knownSvcs := make(map[string]bool)
			for _, s := range resp.Services {
				knownSvcs[s.Name] = true
			}
			type extraSvcRow struct {
				Name         string `json:"name"`
				Namespace    string `json:"namespace"`
				ServiceType  string `json:"service_type"`
				PortsJSON    string `gorm:"column:ports_json"`
				SelectorJSON string `gorm:"column:selector_json"`
			}
			var extraSvcs []extraSvcRow
			db.Raw(liveCTE+`
				SELECT DISTINCT
					s.data->>'name' AS name,
					s.data->>'namespace' AS namespace,
					COALESCE(s.data->>'service_type', '') AS service_type,
					COALESCE(s.data->'ports'::text, '[]') AS ports_json,
					COALESCE(s.data->'selector'::text, '{}') AS selector_json
				FROM live s, live c
				WHERE s.data->>'kind' = 'Service'
				  AND s.data->>'cluster_id' = ?
				  AND s.data->>'namespace' = ?
				  AND s.data->>'service_type' IN ('LoadBalancer', 'NodePort')
				  AND c.data->>'kind' = 'Container'
				  AND c.data->>'pod_phase' = 'Running'
				  AND c.data->>'cluster_id' = ?
				  AND c.data->>'namespace' = ?
				  AND jsonb_typeof(s.data->'selector') = 'object'
				  AND (c.data->'pod_labels') @> (s.data->'selector')
				  AND c.data->>'owner' IN (?)
			`, clusterID, namespace, clusterID, namespace,
				func() []string {
					owners := make([]string, 0)
					seen := make(map[string]bool)
					for _, p := range resp.Pods {
						if !seen[p.Owner] {
							owners = append(owners, p.Owner)
							seen[p.Owner] = true
						}
					}
					return owners
				}(),
			).Scan(&extraSvcs)

			for _, es := range extraSvcs {
				if knownSvcs[es.Name] {
					continue
				}
				cs := chainService{
					Name: es.Name, Namespace: es.Namespace, ServiceType: es.ServiceType,
				}
				if es.PortsJSON != "" {
					_ = json.Unmarshal([]byte(es.PortsJSON), &cs.Ports)
				}
				if es.SelectorJSON != "" {
					_ = json.Unmarshal([]byte(es.SelectorJSON), &cs.Selector)
				}
				resp.Services = append(resp.Services, cs)
			}
		}

		// --- Step 5: For services with no pods, look up EndpointSlice IPs and ports ---
		for i := range resp.Services {
			if resp.Services[i].PodCount == 0 {
				type epRow struct {
					Addresses string `gorm:"column:addresses"`
				}
				var eps []epRow
				db.Raw(liveCTE+`
					SELECT jsonb_array_elements_text(
						jsonb_array_elements(data->'endpoints')->'addresses'
					) AS addresses
					FROM live
					WHERE data->>'kind' = 'EndpointSlice'
					  AND data->>'cluster_id' = ?
					  AND data->>'namespace' = ?
					  AND data->>'service_name' = ?
				`, clusterID, namespace, resp.Services[i].Name).Scan(&eps)
				seen := make(map[string]bool)
				for _, ep := range eps {
					if ep.Addresses != "" && !seen[ep.Addresses] {
						resp.Services[i].EndpointIPs = append(resp.Services[i].EndpointIPs, ep.Addresses)
						seen[ep.Addresses] = true
					}
				}
				// Get endpoint ports (from the EndpointSlice, not the Service)
				type epPortRow struct {
					Port int `gorm:"column:port"`
				}
				var epPorts []epPortRow
				db.Raw(liveCTE+`
					SELECT DISTINCT (p->>'port')::int AS port
					FROM live, jsonb_array_elements(data->'ports') AS p
					WHERE data->>'kind' = 'EndpointSlice'
					  AND data->>'cluster_id' = ?
					  AND data->>'namespace' = ?
					  AND data->>'service_name' = ?
					  AND p->>'port' IS NOT NULL
				`, clusterID, namespace, resp.Services[i].Name).Scan(&epPorts)
				for _, p := range epPorts {
					resp.Services[i].EndpointPorts = append(resp.Services[i].EndpointPorts, p.Port)
				}
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
