package scam

import (
	"context"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"log"
	"net"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/NorskHelsenett/spam/internal/assets"
	"github.com/NorskHelsenett/spam/internal/cache"
	"github.com/NorskHelsenett/spam/internal/clustersummary"
	spamdb "github.com/NorskHelsenett/spam/internal/db"
	"github.com/NorskHelsenett/spam/internal/events"
	"github.com/NorskHelsenett/spam/internal/hostexposure"
	"gorm.io/datatypes"
	"gorm.io/gorm"
)

const maxBodySize = 10 << 20 // 10 MiB

// upsertItem is one observation in a callcenter batch — the JSONB
// payload that lands in cluster_record plus enough out-of-band state
// to populate the first-class columns without JSONB-extracting every
// row. `msg` derives is_present/tombstoned_at; `eventID` advances the
// per-cluster ACK counter (0 when older agents don't send one, in
// which case GREATEST in the upsert preserves the existing value).
// Defined at package scope so helpers like ensureRecentScansForBatch
// can take a typed slice.
type upsertItem struct {
	data    datatypes.JSON
	msg     string
	eventID uint64
}

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
//   - DISTINCT ON takes the latest non-DELETE row per resource (belt-
//     and-braces against any residual msg-duplication; the
//     20260420_dedupe_cluster_record_msg migration plus the resource-
//     keyed unique index normally guarantee this).
//   - Join to cluster_sessions filters out silent clusters whose
//     agent hasn't heartbeated within sessionLiveWindow. Heartbeats
//     and data pushes both bump last_push_at, so a quiet-but-alive
//     cluster stays visible. We deliberately don't gate on
//     session_started_at — agent reconnects shouldn't wipe prior
//     resources, since the agent doesn't reliably re-INITIAL.
//
// Every live-state query reads FROM live and gets both behaviours
// for free — no per-query session-filter boilerplate.
var liveCTE = buildLiveCTE(false)

// allCTE is the same CTE without the liveness predicate — used by
// endpoints that let the operator opt into seeing silent/inactive
// clusters (see `?include_inactive=true`). Still honours the
// resource-identity DISTINCT and the msg!='DELETE' guard.
var allCTE = buildLiveCTE(true)

func buildLiveCTE(includeInactive bool) string {
	return buildLiveCTEWithACL(includeInactive, "")
}

// buildLiveCTEWithACL is the variant that threads an ACL filter into
// the CTE's WHERE clause, so summary-style handlers only see records
// for clusters the caller can read. The fragment is pre-parameterised
// and its bind args are passed separately at handler level.
//
// Passing "" or "TRUE" as the fragment yields the same output as
// buildLiveCTE.
func buildLiveCTEWithACL(includeInactive bool, aclFragment string) string {
	liveness := `AND cs.last_push_at >= NOW() - ` + liveWindowInterval()
	if includeInactive {
		liveness = ""
	}
	aclAnd := ""
	if aclFragment != "" && aclFragment != "TRUE" {
		aclAnd = "AND " + aclFragment
	}
	return `WITH live AS (
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
		  ` + liveness + `
		  ` + aclAnd + `
		ORDER BY cr.data->>'cluster_id',
			CASE WHEN cr.data->>'kind' = 'Container'
			     THEN 'Container:' || (cr.data->>'pod_uid') || '/' || (cr.data->>'container')
			     ELSE (cr.data->>'kind') || ':' || COALESCE(cr.data->>'uid', '')
			END,
			cr.received_at DESC
	) `
}

// cteFor returns allCTE when the request's ?include_inactive query
// param is truthy, otherwise liveCTE. Intended for the /app/clusters
// page endpoints so one toggle in the UI can broaden every data
// source. Detail views (cluster drilldown, chain, etc.) ignore this
// and always use liveCTE.
func cteFor(r *http.Request) string {
	if isTruthy(r.URL.Query().Get("include_inactive")) {
		return allCTE
	}
	return liveCTE
}

// liveCTEForCluster is liveCTE with a per-cluster filter baked into
// the inner WHERE. Cluster_id is bound via a `?` placeholder — callers
// pass it as the FIRST arg to db.Raw, ahead of any other placeholders
// the trailing SELECT introduces.
//
// Use this in detail handlers (chain, host chain, drilldown) where the
// request targets one cluster. The DISTINCT ON dedup then runs over a
// few thousand rows instead of the full multi-cluster table, which is
// the difference between sub-second and upstream-timeout at fleet
// scale. Same liveness + DELETE guards as buildLiveCTE.
var liveCTEForCluster = `WITH live AS (
	SELECT DISTINCT ON (
		cr.data->>'cluster_id',
		CASE WHEN cr.data->>'kind' = 'Container'
		     THEN 'Container:' || (cr.data->>'pod_uid') || '/' || (cr.data->>'container')
		     ELSE (cr.data->>'kind') || ':' || COALESCE(cr.data->>'uid', '')
		END
	) cr.*
	FROM cluster_record cr
	JOIN cluster_sessions cs ON cs.cluster_id = cr.data->>'cluster_id'
	WHERE cr.data->>'cluster_id' = ?
	  AND cr.data->>'msg' != 'DELETE'
	  AND cs.last_push_at >= NOW() - ` + liveWindowInterval() + `
	ORDER BY cr.data->>'cluster_id',
		CASE WHEN cr.data->>'kind' = 'Container'
		     THEN 'Container:' || (cr.data->>'pod_uid') || '/' || (cr.data->>'container')
		     ELSE (cr.data->>'kind') || ':' || COALESCE(cr.data->>'uid', '')
		END,
		cr.received_at DESC
) `

// cteForWithACL is cteFor plus an injected ACL filter on the CTE's
// cluster_id selection. The returned SQL has one `?` placeholder per
// entry in the ACL filter's args slice (handled by the caller).
func cteForWithACL(r *http.Request, aclFragment string) string {
	return buildLiveCTEWithACL(isTruthy(r.URL.Query().Get("include_inactive")), aclFragment)
}

func isTruthy(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

// CallcenterHandler accepts a JSON array of SCAM records, validates each one,
// and upserts live-state rows. DELETE events are stored (not physically removed)
// so the history is preserved. No authentication required.
//
// The cache Store parameter is retained for future per-resource cache work; the
// hosts list now invalidates via the host_exposure MV refresh hook
// (hostexposure.TriggerRefresh) rather than a derived-cache prefix delete, so
// cs itself is currently unused on this path.
func CallcenterHandler(db *gorm.DB, _ cache.Store) http.HandlerFunc {
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
		var rejected int

		// Dedupe by upsert key WITHIN the batch. Postgres disallows a
		// single INSERT … ON CONFLICT DO UPDATE affecting the same row
		// twice (SQLSTATE 21000), so a batch containing both an INITIAL
		// and a later UPDATE for the same resource must collapse to the
		// last one before we build the VALUES list. Last wins, which
		// matches "most recent state".
		keyed := make(map[string]upsertItem)
		order := make([]string, 0, len(raw))
		batchKinds := make(map[string]struct{}, 4)
		// Snapshot records are processed after the regular upsert so a
		// SNAPSHOT key list that arrives in the same batch as fresh
		// CREATE events tombstones only stale rows, not the live ones
		// just upserted (last_change_at < snapshot's now guard).
		var snapshots []Incoming
		// Highest agent-stamped event_id per cluster in this batch;
		// drives the GREATEST advancement of cluster_sessions
		// .last_seen_event_id and feeds the ACK in the push response.
		maxEventIDByCluster := make(map[string]uint64, 1)
		// Per-cluster ROR binding from the nested `ror_metadata` group.
		// Last-wins within a batch — agents emit the same metadata on
		// every line, so the per-record overwrite is cheap and the
		// final value is whatever the agent reported last.
		rorByCluster := make(map[string]*RorMetadata, 1)
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
			if incoming.RorMetadata != nil && incoming.RorMetadata.ClusterID != "" && incoming.ClusterID != "" {
				rorByCluster[incoming.ClusterID] = incoming.RorMetadata
			}
			if incoming.Kind == "Snapshot" {
				snapshots = append(snapshots, incoming)
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
			keyed[key] = upsertItem{
				data:    datatypes.JSON(item),
				msg:     incoming.Msg,
				eventID: incoming.EventID,
			}
			batchKinds[incoming.Kind] = struct{}{}
			if incoming.EventID > maxEventIDByCluster[incoming.ClusterID] {
				maxEventIDByCluster[incoming.ClusterID] = incoming.EventID
			}
		}
		items := make([]upsertItem, 0, len(keyed))
		for _, key := range order {
			items = append(items, keyed[key])
		}

		clusterIDs := make(map[string]struct{}, 4)
		if len(items) > 0 {

			for i := 0; i < len(items); i += 500 {
				end := i + 500
				if end > len(items) {
					end = len(items)
				}
				batch := items[i:end]

				var sb strings.Builder
				args := make([]any, 0, len(batch)*7)
				sb.WriteString("INSERT INTO cluster_record (id, data, received_at, is_present, first_seen_at, last_change_at, tombstoned_at, event_id) VALUES ")
				for j, u := range batch {
					if j > 0 {
						sb.WriteString(", ")
					}
					sb.WriteString("(gen_random_uuid(), ?, ?, ?, ?, ?, ?, ?)")
					isPresent := u.msg != "DELETE"
					var tombstonedAt any
					if !isPresent {
						tombstonedAt = now
					}
					var eventIDArg any
					if u.eventID > 0 {
						eventIDArg = int64(u.eventID)
					}
					args = append(args, u.data, now, isPresent, now, now, tombstonedAt, eventIDArg)
				}
				// On conflict: data/received_at always move forward.
				// last_change_at moves forward ONLY when the record's
				// state actually changed (data content or presence) —
				// that's the column's documented contract from
				// 20260512_cluster_record_lifecycle_columns.sql, and the
				// MV refresh skip relies on it: max(last_change_at) is
				// the source fingerprint for cluster_summary /
				// cluster_image_inventory / host_exposure /
				// exposed_digests, so a no-op heartbeat must not bump it
				// or every snapshot forces a full MV rebuild. Same-batch
				// race protection in applySnapshot is unaffected: brand
				// new rows take the INSERT path (last_change_at = now),
				// and unchanged existing rows are in the snapshot's
				// keep-list. is_present flips both directions (DELETE
				// → false; resource reappearing → true). tombstoned_at
				// preserves the first-tombstone time when staying
				// tombstoned, and clears when the resource comes back.
				// event_id uses GREATEST so out-of-order arrivals (or
				// agents that omit it on some records) don't regress.
				// first_seen_at is intentionally not in the SET clause —
				// it's a write-once column.
				sb.WriteString(` ON CONFLICT (`)
				sb.WriteString(resourceKeyExpr)
				sb.WriteString(`) WHERE (data->>'cluster_id') IS NOT NULL
					DO UPDATE SET
						data = EXCLUDED.data,
						received_at = EXCLUDED.received_at,
						is_present = EXCLUDED.is_present,
						last_change_at = CASE
							WHEN cluster_record.data IS DISTINCT FROM EXCLUDED.data
							  OR cluster_record.is_present IS DISTINCT FROM EXCLUDED.is_present
							THEN EXCLUDED.last_change_at
							ELSE cluster_record.last_change_at
						END,
						tombstoned_at = CASE
							WHEN EXCLUDED.is_present THEN NULL
							ELSE COALESCE(cluster_record.tombstoned_at, EXCLUDED.tombstoned_at)
						END,
						event_id = GREATEST(cluster_record.event_id, EXCLUDED.event_id)`)

				if err := db.Exec(sb.String(), args...).Error; err != nil {
					// Surface the underlying GORM error so silent 500s
					// become diagnosable without a re-deploy.
					log.Printf("callcenter: upsert batch failed (%d rows): %v", len(batch), err)
					http.Error(w, "database error", http.StatusInternalServerError)
					return
				}
			}

			// Collect cluster_ids touched by the upsert; snapshot
			// processing below adds its own.
			for _, item := range items {
				var idOnly struct {
					ClusterID string `json:"cluster_id"`
				}
				if err := json.Unmarshal(item.data, &idOnly); err == nil && idOnly.ClusterID != "" {
					clusterIDs[idOnly.ClusterID] = struct{}{}
				}
			}
		}

		// Apply Snapshot records after the regular upsert. Tombstone
		// rows for (cluster_id, target_kind) whose computed
		// resource-key isn't in resource_keys, gated on
		// `last_change_at < now` so any UPSERTs in this same batch
		// (last_change_at = now) are protected from being immediately
		// reverted. BEGIN/END are markers; only SNAPSHOT mutates.
		for _, snap := range snapshots {
			if snap.ClusterID != "" {
				clusterIDs[snap.ClusterID] = struct{}{}
			}
			if err := applySnapshot(r.Context(), db, snap, now); err != nil {
				log.Printf("callcenter: snapshot apply (cluster=%s target_kind=%s snapshot_id=%s): %v",
					snap.ClusterID, snap.TargetKind, snap.SnapshotID, err)
				// Don't fail the whole batch on snapshot apply errors —
				// regular ingest already succeeded; the periodic safety
				// snapshot will retry.
			}
		}

		// Touch cluster_sessions for everything we just processed —
		// regular records and Snapshots both count as liveness signals.
		// Per-cluster maxEventID drives the GREATEST advancement of
		// last_seen_event_id; snapshot-only batches pass 0 here, which
		// is a no-op against the GREATEST.
		//
		// ROR binding lands after touchClusterSession so the clusters
		// row is guaranteed to exist (first-push insert happens inside
		// touchClusterSession). No-op when the batch carried no
		// ror_metadata for this cluster.
		for clusterID := range clusterIDs {
			if err := touchClusterSession(r.Context(), db, clusterID, now, int64(maxEventIDByCluster[clusterID])); err != nil {
				log.Printf("callcenter: touch session %s: %v", clusterID, err)
			}
			upsertClusterRorBinding(r.Context(), db, clusterID, rorByCluster[clusterID])
		}

		if len(items) > 0 || len(snapshots) > 0 {
			payload, _ := json.Marshal(map[string]any{
				"accepted":  len(items),
				"snapshots": len(snapshots),
				"rejected":  rejected,
			})
			events.DispatchStreamEvent(events.StreamEventScamIngest, payload)
		}

		if len(items) > 0 {

			// Deploy-time scan trigger: for each unique image digest in
			// this batch's Container records, ensure an image_digest row
			// exists and a recent IMAGE_SCAN is queued. UpsertImageDigest
			// no longer eagerly enqueues scans for non-cluster-resident
			// images (e.g. SBOM uploads from CI), so the scan actually
			// triggers here — exactly when an image hits a cluster.
			//
			// Runs asynchronously with a 30s budget so a slow scan-
			// enqueue path doesn't extend the ingest latency the agent
			// sees. Idempotent via the ux_jobs_image_scan_active partial
			// unique index.
			go ensureRecentScansForBatch(db, items)

			// Fresh ingest may change which URLs exist and which images
			// sit on a publicly-served path. Trigger a host_exposure +
			// exposed_digests refresh so the next /api/clusters/hosts
			// (and triage's internet_exposed signal) lands on warm
			// projections. The trigger is debounced — high-volume
			// Container ingest coalesces into one inflight + one
			// pending refresh rather than re-running the chain on
			// every batch. resolve: / hostmeta: / hostfav: caches are
			// intentionally not touched (they track host-external
			// state).
			for kind := range batchKinds {
				if hostExposureRelevantKinds[kind] {
					hostexposure.TriggerRefresh(db)
					break
				}
			}

			// cluster_summary aggregates Container/Ingress/HTTPRoute
			// counts per cluster. The same kind set that moves
			// host_exposure also moves the summary, so reuse the
			// detection above. Refresh is debounced via its own gate.
			for kind := range batchKinds {
				if clusterSummaryRelevantKinds[kind] {
					clustersummary.TriggerRefresh(db)
					break
				}
			}
		}

		// SCAM's PushLoop reads last_seen_event_id from the response
		// and compares to its local last-pushed event_id; on mismatch
		// it fires a reconcile snapshot. Single-cluster batches are
		// the common case (one agent = one cluster); we ack the first
		// cluster encountered, which is that cluster.
		var ackLastSeen int64
		if len(items) > 0 {
			var first struct {
				ClusterID string `json:"cluster_id"`
			}
			if err := json.Unmarshal(items[0].data, &first); err == nil && first.ClusterID != "" {
				ackLastSeen = lookupLastSeenEventID(r.Context(), db, first.ClusterID)
			}
		}

		writeJSON(w, http.StatusOK, ingestResponse{
			Accepted:        len(items),
			Snapshots:       len(snapshots),
			Rejected:        rejected,
			LastSeenEventID: ackLastSeen,
		})
	}
}

// applySnapshot processes one Snapshot record. BEGIN/END are markers
// (logged for forensics, no DB mutation). SNAPSHOT performs the
// reconcile: tombstone every still-present row in
// (cluster_id, target_kind) whose computed resource-key is NOT in
// resource_keys AND whose last_change_at predates this snapshot's
// reference time (so rows upserted in the same batch as the snapshot
// are protected).
//
// `data->>'msg'` is dual-written to "DELETE" so existing readers that
// haven't been swept to the is_present filter still see tombstoned
// rows as deleted.
func applySnapshot(ctx context.Context, db *gorm.DB, snap Incoming, now time.Time) error {
	switch snap.Msg {
	case "SNAPSHOT_BEGIN":
		log.Printf("snapshot: BEGIN cluster=%s id=%s type=%s",
			snap.ClusterID, snap.SnapshotID, snap.SnapshotType)
		return nil
	case "SNAPSHOT_END":
		log.Printf("snapshot: END cluster=%s id=%s",
			snap.ClusterID, snap.SnapshotID)
		return nil
	case "SNAPSHOT":
		// fall through
	default:
		return fmt.Errorf("applySnapshot: unsupported msg %q", snap.Msg)
	}

	// Compute resource-key the same way the unique index does so the
	// tombstone WHERE filter matches the rows that would conflict with
	// a real upsert. Container has a composite (pod_uid/container)
	// key; everything else is uid.
	var keyExpr string
	if snap.TargetKind == "Container" {
		keyExpr = `(data->>'pod_uid') || '/' || (data->>'container')`
	} else {
		keyExpr = `COALESCE(data->>'uid', '')`
	}

	keys := snap.ResourceKeys
	if keys == nil {
		keys = []string{}
	}
	// Bind as JSON: GORM expands a Go []string into a comma-separated
	// list of `?` placeholders (the usual IN-clause trick), which
	// turns ANY(?::text[]) into a syntax error. Round-tripping through
	// jsonb_array_elements_text keeps the parameter to a single string,
	// avoids the array-literal escape rules, and degenerates correctly
	// to "tombstone everything" when the slice is empty.
	keysJSON, err := json.Marshal(keys)
	if err != nil {
		return fmt.Errorf("snapshot: marshal keys: %w", err)
	}

	var snapshotIDArg any
	if snap.SnapshotID != "" {
		snapshotIDArg = snap.SnapshotID
	}

	sql := `
		UPDATE cluster_record
		SET is_present = FALSE,
		    tombstoned_at = COALESCE(tombstoned_at, ?),
		    last_change_at = ?,
		    last_snapshot_id = ?,
		    data = jsonb_set(data, '{msg}', '"DELETE"')
		WHERE data->>'cluster_id' = ?
		  AND data->>'kind' = ?
		  AND is_present = TRUE
		  AND last_change_at < ?
		  AND ` + keyExpr + ` NOT IN (
		    SELECT jsonb_array_elements_text(?::jsonb)
		  )`

	return db.WithContext(ctx).Exec(sql,
		now,              // tombstoned_at fallback
		now,              // last_change_at
		snapshotIDArg,    // last_snapshot_id (nullable)
		snap.ClusterID,   // cluster_id
		snap.TargetKind,  // kind
		now,              // race-protection cutoff
		string(keysJSON), // resource_keys as JSON array string
	).Error
}

// ensureRecentScansForBatch is the scam ingest's deploy-time scan
// trigger. For each unique (registry, repository, digest) tuple in the
// batch's Container records, it ensures an image_digests row exists
// and a recent IMAGE_SCAN job is queued (see assets.EnsureImageScanRecent
// for freshness semantics). Skips DELETE / non-Container / digest-less
// records.
func ensureRecentScansForBatch(db *gorm.DB, items []upsertItem) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Dedupe by digest within the batch — multiple pods of the same
	// image collapse to a single scan-enqueue attempt.
	unique := make(map[string]assets.ImageDigestInput, len(items))
	for _, item := range items {
		var inc Incoming
		if err := json.Unmarshal(item.data, &inc); err != nil {
			continue
		}
		if inc.Kind != "Container" || inc.Msg == "DELETE" {
			continue
		}
		if inc.Digest == "" || inc.Registry == "" || inc.Image == "" {
			continue
		}
		unique[inc.Digest] = assets.ImageDigestInput{
			Registry:   inc.Registry,
			Repository: inc.Image,
			Digest:     inc.Digest,
		}
	}

	for _, in := range unique {
		image, err := assets.UpsertImageDigest(ctx, db, in)
		if err != nil {
			log.Printf("scam: ensure image_digest %s/%s@%s: %v",
				in.Registry, in.Repository, in.Digest, err)
			continue
		}
		// UpsertImageDigest only auto-enqueues for *new* rows; for
		// digests we've seen before we still need to ensure scan
		// freshness in case the previous run is now stale.
		if err := assets.EnsureImageScanRecent(ctx, db, image.ID); err != nil {
			log.Printf("scam: ensure scan for %s: %v", image.ID, err)
		}
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
		if err := touchClusterSession(r.Context(), db, body.ClusterID, time.Now().UTC(), 0); err != nil {
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
	// Snapshot records carry no resource identity (uid/pod_uid). They
	// validate their own envelope: BEGIN/END need a snapshot_id, the
	// payload SNAPSHOT needs target_kind plus a (possibly empty) keys
	// slice.
	if r.Kind == "Snapshot" {
		switch r.Msg {
		case "SNAPSHOT_BEGIN", "SNAPSHOT_END":
			if r.SnapshotID == "" {
				return fmt.Errorf("%s missing snapshot_id", r.Msg)
			}
		case "SNAPSHOT":
			if r.TargetKind == "" {
				return fmt.Errorf("SNAPSHOT missing target_kind")
			}
			if !validKinds[r.TargetKind] || r.TargetKind == "Snapshot" {
				return fmt.Errorf("SNAPSHOT invalid target_kind: %s", r.TargetKind)
			}
		default:
			return fmt.Errorf("Snapshot kind requires SNAPSHOT / SNAPSHOT_BEGIN / SNAPSHOT_END msg")
		}
		return nil
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

// ClusterSummaryHandler returns a high-level overview per cluster. Reads
// from the cluster_summary materialised view (see
// 20260510a_create_cluster_summary_view.sql); freshness is ingest-driven
// via clustersummary.TriggerRefresh from the CallcenterHandler hook.
//
// The MV does not embed the cluster_sessions liveness filter — that
// depends on NOW() and is per-request — so the handler joins
// cluster_sessions here when ?include_inactive isn't truthy.
func ClusterSummaryHandler(db *gorm.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// scanRow matches cluster_summary MV columns. ROR fields are
		// nullable so an absent binding marshals to a missing
		// ror_metadata object on the wire rather than a triple of empty
		// strings — the frontend uses presence/absence of ror_metadata
		// as the signal for "ROR was sent" vs "env-var fallback only,"
		// which is what an operator wants to see when debugging a
		// helm-configured cluster that hasn't bound to ROR yet.
		type scanRow struct {
			ClusterID      string    `gorm:"column:cluster_id"`
			ClusterName    *string   `gorm:"column:cluster_name"`
			RorSlug        *string   `gorm:"column:ror_slug"`
			RorClusterName *string   `gorm:"column:ror_cluster_name"`
			RorEnv         *string   `gorm:"column:ror_env"`
			Environment    string    `gorm:"column:environment"`
			Containers     int64     `gorm:"column:containers"`
			Images         int64     `gorm:"column:images"`
			Namespaces     int64     `gorm:"column:namespaces"`
			IngressCount   int64     `gorm:"column:ingress_count"`
			LastSeen       time.Time `gorm:"column:last_seen"`
		}
		// rorMetadata is the nested object on the wire; omitempty so
		// it disappears entirely for clusters without a ROR binding.
		type rorMetadata struct {
			Slug        string `json:"slug,omitempty"`
			ClusterName string `json:"cluster_name,omitempty"`
			Env         string `json:"env,omitempty"`
		}
		type outRow struct {
			ClusterID    string       `json:"cluster_id"`
			ClusterName  string       `json:"cluster_name,omitempty"`
			RorMetadata  *rorMetadata `json:"ror_metadata,omitempty"`
			Environment  string       `json:"environment,omitempty"`
			Containers   int64        `json:"containers"`
			Images       int64        `json:"images"`
			Namespaces   int64        `json:"namespaces"`
			IngressCount int64        `json:"ingress_count"`
			LastSeen     time.Time    `json:"last_seen"`
		}
		out := []outRow{}
		ctx := r.Context()

		aclFrag, aclArgs, deny := clusterACLFilterCol(r, "cs.cluster_id")
		if deny {
			writeJSON(w, http.StatusOK, out)
			return
		}

		// Cold-start: the MV is created WITH NO DATA. Refreshes run
		// asynchronously at boot and on every relevant ingest. If we
		// catch it before the first populate, return an empty list and
		// kick a refresh so the next request lands warm — avoids the
		// SQLSTATE 55000 a bare SELECT would raise.
		if ready, err := spamdb.ClusterSummaryViewPopulated(ctx, db); err != nil || !ready {
			clustersummary.TriggerRefresh(db)
			writeJSON(w, http.StatusOK, out)
			return
		}

		includeInactive := isTruthy(r.URL.Query().Get("include_inactive"))
		livenessJoin := "JOIN cluster_sessions sess ON sess.cluster_id = cs.cluster_id AND sess.last_push_at >= NOW() - " + liveWindowInterval()
		if includeInactive {
			livenessJoin = ""
		}

		aclWhere := ""
		if aclFrag != "" && aclFrag != "TRUE" {
			aclWhere = "AND " + aclFrag
		}

		// Free-text search hits all four name surfaces (cluster_id,
		// env-var label, ROR slug, ROR friendly name) plus environment.
		// An operator can find a cluster by whichever string they know;
		// cluster list is small enough that scanning all four with ILIKE
		// stays cheap.
		searchQuery := strings.TrimSpace(r.URL.Query().Get("q"))
		searchWhere := ""
		var searchArgs []any
		if searchQuery != "" {
			pattern := "%" + searchQuery + "%"
			searchWhere = `AND (
				cs.cluster_id        ILIKE ? OR
				cs.cluster_name      ILIKE ? OR
				cs.ror_slug          ILIKE ? OR
				cs.ror_cluster_name  ILIKE ? OR
				cs.environment       ILIKE ?
			)`
			searchArgs = []any{pattern, pattern, pattern, pattern, pattern}
		}

		query := `
			SELECT
			    cs.cluster_id, cs.cluster_name,
			    cs.ror_slug, cs.ror_cluster_name, cs.ror_env,
			    cs.environment,
			    cs.containers, cs.images, cs.namespaces, cs.ingress_count,
			    cs.last_seen
			FROM cluster_summary cs
			` + livenessJoin + `
			WHERE TRUE ` + aclWhere + ` ` + searchWhere + `
			ORDER BY cs.last_seen DESC
		`
		queryArgs := append([]any{}, aclArgs...)
		queryArgs = append(queryArgs, searchArgs...)
		var rows []scanRow
		if err := db.WithContext(ctx).Raw(query, queryArgs...).Scan(&rows).Error; err != nil {
			log.Printf("ClusterSummaryHandler query error: %v", err)
			http.Error(w, "query failed", http.StatusInternalServerError)
			return
		}
		out = make([]outRow, 0, len(rows))
		for _, r := range rows {
			row := outRow{
				ClusterID:    r.ClusterID,
				Environment:  r.Environment,
				Containers:   r.Containers,
				Images:       r.Images,
				Namespaces:   r.Namespaces,
				IngressCount: r.IngressCount,
				LastSeen:     r.LastSeen,
			}
			if r.ClusterName != nil {
				row.ClusterName = *r.ClusterName
			}
			// ROR triple is all-or-nothing: when no record carried
			// ror_metadata, every ROR column is NULL and the nested
			// object is omitted entirely. Gate the object on slug
			// presence because slug is the load-bearing identifier
			// (name/env can be empty strings even when a binding
			// exists; slug is always present when ror_metadata is).
			if r.RorSlug != nil {
				meta := &rorMetadata{Slug: *r.RorSlug}
				if r.RorClusterName != nil {
					meta.ClusterName = *r.RorClusterName
				}
				if r.RorEnv != nil {
					meta.Env = *r.RorEnv
				}
				row.RorMetadata = meta
			}
			out = append(out, row)
		}
		writeJSON(w, http.StatusOK, out)
	}
}

// RegistryDistributionHandler returns unique image counts by registry.
// Reads from cluster_image_inventory (see
// 20260511_create_cluster_image_inventory_view.sql); freshness is
// ingest-driven via clustersummary.TriggerRefresh from CallcenterHandler.
//
// Output cardinality is bounded by the number of registries in the
// fleet (typically tens), so this endpoint isn't paginated.
func RegistryDistributionHandler(db *gorm.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		type row struct {
			Registry   string `json:"registry"`
			ImageCount int64  `json:"image_count"`
		}
		rows := []row{}
		ctx := r.Context()

		aclFrag, aclArgs, deny := clusterACLFilterCol(r, "cii.cluster_id")
		if deny {
			writeJSON(w, http.StatusOK, rows)
			return
		}

		// Cold-start gate: MV created WITH NO DATA. Kick a refresh
		// and return empty so the first request after fresh deploy
		// doesn't raise SQLSTATE 55000.
		if ready, err := spamdb.ClusterImageInventoryPopulated(ctx, db); err != nil || !ready {
			clustersummary.TriggerRefresh(db)
			writeJSON(w, http.StatusOK, rows)
			return
		}

		includeInactive := isTruthy(r.URL.Query().Get("include_inactive"))
		livenessJoin := ""
		if !includeInactive {
			livenessJoin = "JOIN cluster_sessions sess ON sess.cluster_id = cii.cluster_id AND sess.last_push_at >= NOW() - " + liveWindowInterval()
		}

		aclWhere := ""
		if aclFrag != "" && aclFrag != "TRUE" {
			aclWhere = "AND " + aclFrag
		}

		query := `
			SELECT
			    cii.registry,
			    COUNT(DISTINCT (cii.raw_registry || '/' || cii.image || '@' || cii.digest))::bigint AS image_count
			FROM cluster_image_inventory cii
			` + livenessJoin + `
			WHERE TRUE ` + aclWhere + `
			GROUP BY cii.registry
			ORDER BY image_count DESC
		`

		if err := db.WithContext(ctx).Raw(query, aclArgs...).Scan(&rows).Error; err != nil {
			log.Printf("RegistryDistributionHandler query error: %v", err)
			http.Error(w, "query failed", http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, rows)
	}
}

// ImageFacetsHandler returns the dropdown option sets for the Images
// tab — registries, clusters, namespaces — each one computed against
// the current search + the OTHER two filter dimensions. Mirrors the
// hostFacets pattern: a selection in dimension X doesn't shrink the X
// dropdown (so the user can deselect / add more values), but does
// shrink the others so cross-filtering converges quickly.
//
// One round-trip serves all three lists so the frontend stays in sync
// with itself — three separate endpoints would risk a race where, say,
// the namespace list narrows before the cluster list catches up.
func ImageFacetsHandler(db *gorm.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		type registryFacet struct {
			Registry   string `json:"registry"`
			ImageCount int64  `json:"image_count"`
		}
		type clusterFacet struct {
			ID    string `json:"id"`
			Label string `json:"label"`
		}
		type response struct {
			Registries []registryFacet `json:"registries"`
			Clusters   []clusterFacet  `json:"clusters"`
			Namespaces []string        `json:"namespaces"`
		}
		ctx := r.Context()
		resp := response{Registries: []registryFacet{}, Clusters: []clusterFacet{}, Namespaces: []string{}}

		aclFrag, aclArgs, deny := clusterACLFilterCol(r, "cii.cluster_id")
		if deny {
			writeJSON(w, http.StatusOK, resp)
			return
		}

		if ready, err := spamdb.ClusterImageInventoryPopulated(ctx, db); err != nil || !ready {
			clustersummary.TriggerRefresh(db)
			writeJSON(w, http.StatusOK, resp)
			return
		}

		includeInactive := isTruthy(r.URL.Query().Get("include_inactive"))
		livenessJoin := ""
		if !includeInactive {
			livenessJoin = "JOIN cluster_sessions sess ON sess.cluster_id = cii.cluster_id AND sess.last_push_at >= NOW() - " + liveWindowInterval()
		}

		aclWhere := ""
		if aclFrag != "" && aclFrag != "TRUE" {
			aclWhere = "AND " + aclFrag
		}

		searchQuery := strings.TrimSpace(r.URL.Query().Get("q"))
		registries := parseImageFilterCSV(r.URL.Query().Get("registries"))
		clusterIDs := parseImageFilterCSV(r.URL.Query().Get("cluster_ids"))
		namespaces := parseImageFilterCSV(r.URL.Query().Get("namespaces"))

		// buildWhere assembles the pre-GROUP-BY filter fragment for a
		// facet query. The three include* flags let each facet skip its
		// own dimension — that's the bit that keeps the registry dropdown
		// from collapsing to a single row when the user selects one
		// registry, etc.
		buildWhere := func(includeReg, includeCl, includeNs bool) (string, []any) {
			var where string
			var args []any
			if searchQuery != "" {
				pattern := "%" + searchQuery + "%"
				where += `AND (cii.registry ILIKE ? OR cii.image ILIKE ? OR cii.digest ILIKE ? OR cii.tag ILIKE ?) `
				args = append(args, pattern, pattern, pattern, pattern)
			}
			if includeReg && len(registries) > 0 {
				ph := strings.TrimRight(strings.Repeat("?,", len(registries)), ",")
				where += `AND cii.registry IN (` + ph + `) `
				for _, v := range registries {
					args = append(args, v)
				}
			}
			if includeCl && len(clusterIDs) > 0 {
				ph := strings.TrimRight(strings.Repeat("?,", len(clusterIDs)), ",")
				where += `AND cii.cluster_id IN (` + ph + `) `
				for _, v := range clusterIDs {
					args = append(args, v)
				}
			}
			if includeNs && len(namespaces) > 0 {
				ph := strings.TrimRight(strings.Repeat("?,", len(namespaces)), ",")
				where += `AND cii.namespace IN (` + ph + `) `
				for _, v := range namespaces {
					args = append(args, v)
				}
			}
			return where, args
		}

		// Registry facet — skip the registry dimension, keep cluster + ns.
		regWhere, regArgs := buildWhere(false, true, true)
		regQuery := `
			SELECT cii.registry,
			       COUNT(DISTINCT (cii.raw_registry || '/' || cii.image || '@' || cii.digest))::bigint AS image_count
			FROM cluster_image_inventory cii
			` + livenessJoin + `
			WHERE TRUE ` + aclWhere + ` ` + regWhere + `
			GROUP BY cii.registry
			ORDER BY image_count DESC
		`
		regFullArgs := append([]any{}, aclArgs...)
		regFullArgs = append(regFullArgs, regArgs...)
		if err := db.WithContext(ctx).Raw(regQuery, regFullArgs...).Scan(&resp.Registries).Error; err != nil {
			log.Printf("ImageFacetsHandler registry query error: %v", err)
			http.Error(w, "query failed", http.StatusInternalServerError)
			return
		}

		// Cluster facet — skip the cluster dimension. Label COALESCE
		// matches displayClusterName on the frontend (ROR friendly →
		// env-var label → ROR slug → cluster_id) so the dropdown text
		// lines up with what the cluster table shows.
		clWhere, clArgs := buildWhere(true, false, true)
		clQuery := `
			SELECT DISTINCT cii.cluster_id AS id,
			       COALESCE(NULLIF(cs.ror_cluster_name, ''),
			                NULLIF(cs.cluster_name, ''),
			                NULLIF(cs.ror_slug, ''),
			                cii.cluster_id) AS label
			FROM cluster_image_inventory cii
			LEFT JOIN cluster_summary cs ON cs.cluster_id = cii.cluster_id
			` + livenessJoin + `
			WHERE TRUE ` + aclWhere + ` ` + clWhere + `
			ORDER BY label
		`
		clFullArgs := append([]any{}, aclArgs...)
		clFullArgs = append(clFullArgs, clArgs...)
		if err := db.WithContext(ctx).Raw(clQuery, clFullArgs...).Scan(&resp.Clusters).Error; err != nil {
			log.Printf("ImageFacetsHandler cluster query error: %v", err)
			http.Error(w, "query failed", http.StatusInternalServerError)
			return
		}

		// Namespace facet — skip the namespace dimension.
		nsWhere, nsArgs := buildWhere(true, true, false)
		nsQuery := `
			SELECT DISTINCT cii.namespace
			FROM cluster_image_inventory cii
			` + livenessJoin + `
			WHERE TRUE ` + aclWhere + ` ` + nsWhere + ` AND cii.namespace <> ''
			ORDER BY cii.namespace
		`
		nsFullArgs := append([]any{}, aclArgs...)
		nsFullArgs = append(nsFullArgs, nsArgs...)
		if err := db.WithContext(ctx).Raw(nsQuery, nsFullArgs...).Scan(&resp.Namespaces).Error; err != nil {
			log.Printf("ImageFacetsHandler namespace query error: %v", err)
			http.Error(w, "query failed", http.StatusInternalServerError)
			return
		}

		writeJSON(w, http.StatusOK, resp)
	}
}

// parseImageFilterCSV splits a comma-separated query param into trimmed
// non-empty values. Shared between ImageDetailHandler's filter args and
// ImageFacetsHandler so both parse identically.
func parseImageFilterCSV(raw string) []string {
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// ExposureHandler returns internet vs internal resource counts.
func ExposureHandler(db *gorm.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		type result struct {
			InternetExposed  int64 `json:"internet_exposed"`
			InternalServices int64 `json:"internal_services"`
		}
		var res result
		aclFrag, aclArgs, deny := clusterACLFilter(r)
		if deny {
			writeJSON(w, http.StatusOK, res)
			return
		}
		err := db.Raw(buildLiveCTEWithACL(false, aclFrag)+`
			SELECT
				COUNT(DISTINCT data->>'uid') FILTER (
					WHERE data->>'kind' IN ('Ingress','HTTPRoute','GRPCRoute','IngressRoute','IngressRouteTCP')
				) AS internet_exposed,
				COUNT(DISTINCT data->>'uid') FILTER (
					WHERE data->>'kind' = 'Service'
				) AS internal_services
			FROM live
		`, aclArgs...).Scan(&res).Error
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
//
// Reads from cluster_image_inventory (per running container) and
// aggregates at request time so ACL on cluster_id can apply before the
// GROUP BY. Paginated via ?limit/?offset with a has_more flag — the
// dependencies endpoint pattern, mirrored here so the frontend can
// infinite-scroll without loading 10k+ rows up front.
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
		type response struct {
			Items   []row `json:"items"`
			Limit   int   `json:"limit"`
			Offset  int   `json:"offset"`
			HasMore bool  `json:"has_more"`
			Total   int64 `json:"total"`
		}

		ctx := r.Context()
		rows := []row{}

		aclFrag, aclArgs, deny := clusterACLFilterCol(r, "cii.cluster_id")
		if deny {
			writeJSON(w, http.StatusOK, response{Items: rows})
			return
		}

		// Cold-start gate.
		if ready, err := spamdb.ClusterImageInventoryPopulated(ctx, db); err != nil || !ready {
			clustersummary.TriggerRefresh(db)
			writeJSON(w, http.StatusOK, response{Items: rows})
			return
		}

		limit := 50
		if v := r.URL.Query().Get("limit"); v != "" {
			if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 200 {
				limit = n
			}
		}
		offset := 0
		if v := r.URL.Query().Get("offset"); v != "" {
			if n, err := strconv.Atoi(v); err == nil && n >= 0 {
				offset = n
			}
		}

		includeInactive := isTruthy(r.URL.Query().Get("include_inactive"))
		livenessJoin := ""
		if !includeInactive {
			livenessJoin = "JOIN cluster_sessions sess ON sess.cluster_id = cii.cluster_id AND sess.last_push_at >= NOW() - " + liveWindowInterval()
		}

		aclWhere := ""
		if aclFrag != "" && aclFrag != "TRUE" {
			aclWhere = "AND " + aclFrag
		}

		// Free-text search across the row-level fields the frontend
		// table used to filter client-side. Pre-aggregate filter so the
		// GROUP BY counts (cluster_count, container_count, etc.) reflect
		// only the matched rows.
		searchQuery := strings.TrimSpace(r.URL.Query().Get("q"))
		var preGroupWhere string
		var preGroupArgs []any
		if searchQuery != "" {
			pattern := "%" + searchQuery + "%"
			preGroupWhere += `AND (cii.registry ILIKE ? OR cii.image ILIKE ? OR cii.digest ILIKE ? OR cii.tag ILIKE ?) `
			preGroupArgs = append(preGroupArgs, pattern, pattern, pattern, pattern)
		}
		// Registry multi-select. Matches on cii.registry (the display
		// registry) so the values line up with /api/clusters/registry-
		// distribution, which is what the frontend populates the
		// dropdown options from. raw_registry holds the unnormalised
		// pull-spec prefix and was the wrong field to filter on — most
		// fleets normalise docker.io / index.docker.io variants in
		// cii.registry but not in cii.raw_registry.
		if rawReg := r.URL.Query().Get("registries"); rawReg != "" {
			values := []any{}
			for _, v := range strings.Split(rawReg, ",") {
				if v = strings.TrimSpace(v); v != "" {
					values = append(values, v)
				}
			}
			if len(values) > 0 {
				placeholders := strings.TrimRight(strings.Repeat("?,", len(values)), ",")
				preGroupWhere += `AND cii.registry IN (` + placeholders + `) `
				preGroupArgs = append(preGroupArgs, values...)
			}
		}
		// Cluster multi-select. Mirrors the Hosts tab cluster filter so
		// the Images tab can scope down to one (or several) clusters
		// without round-tripping a per-cluster endpoint.
		if rawClusters := r.URL.Query().Get("cluster_ids"); rawClusters != "" {
			values := []any{}
			for _, v := range strings.Split(rawClusters, ",") {
				if v = strings.TrimSpace(v); v != "" {
					values = append(values, v)
				}
			}
			if len(values) > 0 {
				placeholders := strings.TrimRight(strings.Repeat("?,", len(values)), ",")
				preGroupWhere += `AND cii.cluster_id IN (` + placeholders + `) `
				preGroupArgs = append(preGroupArgs, values...)
			}
		}
		// Namespace multi-select. Same shape as registries/cluster_ids —
		// applied pre-GROUP BY so cluster_count / container_count reflect
		// only the rows in the selected namespaces.
		if rawNs := r.URL.Query().Get("namespaces"); rawNs != "" {
			values := []any{}
			for _, v := range strings.Split(rawNs, ",") {
				if v = strings.TrimSpace(v); v != "" {
					values = append(values, v)
				}
			}
			if len(values) > 0 {
				placeholders := strings.TrimRight(strings.Repeat("?,", len(values)), ",")
				preGroupWhere += `AND cii.namespace IN (` + placeholders + `) `
				preGroupArgs = append(preGroupArgs, values...)
			}
		}

		// Sort allowlist — never interpolate user input into ORDER BY.
		// The vuln_weight column in the inventory_with_vulns CTE lets
		// 'vulns' sort server-side using the same severity weighting
		// the frontend used for its in-memory sort, so the table order
		// is identical to the old client-side sort but spans the whole
		// dataset rather than the loaded page.
		sortColumn, sortDirection := parseImageSortParams(r.URL.Query().Get("sort"), r.URL.Query().Get("order"))

		// inventory + digest_id + vuln_counts must be materialised
		// *before* the page LIMIT so sorts on columns derived from
		// outside cluster_image_inventory (vulns) include digests in
		// the right global order rather than just within the page.
		// latest_scan is scoped to inventory digests via the IN clause
		// — bounded work even though we no longer restrict to the page.
		// limit+1 gives us has_more without a second COUNT query.
		query := `
			WITH inventory AS (
				SELECT
				    cii.raw_registry, cii.registry, cii.image, cii.digest,
				    STRING_AGG(DISTINCT cii.tag, ',' ORDER BY cii.tag) FILTER (WHERE cii.tag IS NOT NULL AND cii.tag <> '') AS tags,
				    COUNT(DISTINCT cii.cluster_id)::bigint AS cluster_count,
				    COUNT(DISTINCT cii.namespace)::bigint  AS namespace_count,
				    COUNT(*)::bigint                       AS container_count,
				    MAX(cii.last_seen)                     AS last_seen
				FROM cluster_image_inventory cii
				` + livenessJoin + `
				WHERE TRUE ` + aclWhere + ` ` + preGroupWhere + `
				GROUP BY cii.raw_registry, cii.registry, cii.image, cii.digest
			),
			inventory_digests AS (
				SELECT inv.*, id.id AS digest_id
				FROM inventory inv
				LEFT JOIN image_digests id
				    ON id.registry   = inv.raw_registry
				   AND id.repository = inv.image
				   AND id.digest     = inv.digest
			),
			latest_scan AS (
				SELECT DISTINCT ON (isr.image_digest_id)
				       isr.image_digest_id,
				       isr.id AS scan_run_id
				FROM image_scan_runs isr
				WHERE isr.finished_at IS NOT NULL
				  AND isr.image_digest_id IN (SELECT digest_id FROM inventory_digests WHERE digest_id IS NOT NULL)
				ORDER BY isr.image_digest_id, isr.finished_at DESC
			),
			vuln_counts AS (
				SELECT f.image_digest_id,
				    COUNT(*) FILTER (WHERE UPPER(severity) = 'CRITICAL')            AS vuln_critical,
				    COUNT(*) FILTER (WHERE UPPER(severity) = 'HIGH')                AS vuln_high,
				    COUNT(*) FILTER (WHERE UPPER(severity) = 'MEDIUM')              AS vuln_medium,
				    COUNT(*) FILTER (WHERE UPPER(severity) IN ('LOW','NEGLIGIBLE')) AS vuln_low,
				    COUNT(*) FILTER (WHERE UPPER(severity) NOT IN ('CRITICAL','HIGH','MEDIUM','LOW','NEGLIGIBLE')) AS vuln_unknown,
				    -- Severity-weighted sort key — must match the
				    -- frontend's vulnSortKey exactly so behaviour is
				    -- identical between server-side (current) and any
				    -- legacy client-side path: c*1e9 + h*1e6 + m*1e3 + l.
				    (COUNT(*) FILTER (WHERE UPPER(severity) = 'CRITICAL')::bigint            * 1000000000 +
				     COUNT(*) FILTER (WHERE UPPER(severity) = 'HIGH')::bigint                * 1000000 +
				     COUNT(*) FILTER (WHERE UPPER(severity) = 'MEDIUM')::bigint              * 1000 +
				     COUNT(*) FILTER (WHERE UPPER(severity) IN ('LOW','NEGLIGIBLE'))::bigint) AS vuln_weight
				FROM image_vuln_findings f
				JOIN latest_scan ls ON ls.scan_run_id = f.scan_run_id
				GROUP BY f.image_digest_id
			),
			inventory_with_vulns AS (
				SELECT dl.*,
				    COALESCE(vc.vuln_critical, 0) AS vuln_critical,
				    COALESCE(vc.vuln_high, 0)     AS vuln_high,
				    COALESCE(vc.vuln_medium, 0)   AS vuln_medium,
				    COALESCE(vc.vuln_low, 0)      AS vuln_low,
				    COALESCE(vc.vuln_unknown, 0)  AS vuln_unknown,
				    COALESCE(vc.vuln_weight, 0)   AS vuln_weight
				FROM inventory_digests dl
				LEFT JOIN vuln_counts vc ON vc.image_digest_id = dl.digest_id
			),
			page AS (
				SELECT * FROM inventory_with_vulns
				ORDER BY ` + sortColumn + ` ` + sortDirection + `, image ASC, digest ASC
				LIMIT ? OFFSET ?
			)
			SELECT
			    page.registry, page.image, page.digest,
			    COALESCE(page.digest_id::text, '') AS digest_id,
			    COALESCE(page.tags, '')           AS tags,
			    page.cluster_count, page.namespace_count, page.container_count, page.last_seen,
			    page.vuln_critical, page.vuln_high, page.vuln_medium, page.vuln_low, page.vuln_unknown
			FROM page
			ORDER BY ` + sortColumn + ` ` + sortDirection + `, page.image ASC, page.digest ASC
		`

		args := append([]any{}, aclArgs...)
		args = append(args, preGroupArgs...)
		args = append(args, limit+1, offset)

		if err := db.WithContext(ctx).Raw(query, args...).Scan(&rows).Error; err != nil {
			log.Printf("ImageDetailHandler query error: %v", err)
			http.Error(w, "query failed", http.StatusInternalServerError)
			return
		}

		hasMore := len(rows) > limit
		if hasMore {
			rows = rows[:limit]
		}

		// Total over the same filter scope. Separate query because the
		// LIMIT+1 trick only tells us "is there at least one more"; the
		// frontend wants the absolute count for "showing N of M" and the
		// virtual-scroll height. Cheap when the inventory MV is hot.
		var total int64
		countQuery := `
			SELECT COUNT(DISTINCT (cii.raw_registry, cii.image, cii.digest))::bigint
			FROM cluster_image_inventory cii
			` + livenessJoin + `
			WHERE TRUE ` + aclWhere + ` ` + preGroupWhere + `
		`
		countArgs := append([]any{}, aclArgs...)
		countArgs = append(countArgs, preGroupArgs...)
		if err := db.WithContext(ctx).Raw(countQuery, countArgs...).Scan(&total).Error; err != nil {
			// Soft-fail: serve the page without a total rather than 500.
			log.Printf("ImageDetailHandler count error: %v", err)
		}

		writeJSON(w, http.StatusOK, response{
			Items:   rows,
			Limit:   limit,
			Offset:  offset,
			HasMore: hasMore,
			Total:   total,
		})
	}
}

// hostExposureRelevantKinds is the set of SCAM record kinds whose
// ingest can change either the host_exposure projection (URL-level
// metadata) or the exposed_digests projection (which images sit on a
// publicly-served path). CallcenterHandler triggers a debounced refresh
// when a batch touches one of these — high-volume Container ingest
// coalesces into one inflight + one pending refresh rather than
// recomputing the chain on every batch.
var hostExposureRelevantKinds = map[string]bool{
	"Ingress":         true,
	"HTTPRoute":       true,
	"GRPCRoute":       true,
	"TLSRoute":        true,
	"IngressRoute":    true,
	"IngressRouteTCP": true,
	"Service":         true,
	"Container":       true,
}

// clusterSummaryRelevantKinds is the set of SCAM record kinds whose
// ingest changes one of the columns cluster_summary aggregates:
// container counts (Container), distinct image counts (Container with
// digest), namespace counts (Container.namespace), and ingress_count
// (Ingress / Gateway / Traefik routes). last_seen also moves on any of
// these. Service and TLSRoute don't directly contribute to a column
// but are kept aligned with hostExposureRelevantKinds so the same
// detection covers both.
var clusterSummaryRelevantKinds = map[string]bool{
	"Container":       true,
	"Ingress":         true,
	"HTTPRoute":       true,
	"GRPCRoute":       true,
	"TLSRoute":        true,
	"IngressRoute":    true,
	"IngressRouteTCP": true,
}

// HostRow is the shape returned by HostsHandler. Resolved/Meta are
// inlined from the per-host resolve / hostmeta caches at response time
// (nil on cache miss — the frontend falls back to the per-host
// endpoints, which in turn warm the cache for the next list request).
type HostRow struct {
	Host          string         `json:"host"`
	Kind          string         `json:"kind"`
	Name          string         `json:"name"`
	Namespace     string         `json:"namespace"`
	Cluster       string         `json:"cluster"`
	ClusterID     string         `json:"cluster_id"`
	Environment   string         `json:"environment"`
	TLS           bool           `json:"tls"`
	LBIPs         string         `json:"lb_ips"`
	IngressClass  string         `json:"ingress_class"`
	Backends      string         `json:"backends"`
	WorkloadCount int64          `json:"workload_count"`
	LastSeen      time.Time      `json:"last_seen"`
	Resolved      *resolveResult `json:"resolved,omitempty" gorm:"-"`
	Meta          *hostMetaLite  `json:"meta,omitempty" gorm:"-"`
}

// hostMetaLite is the subset of hostMeta the list response needs.
// The full hostMeta (with internal faviconBytes) stays behind the
// /meta and /favicon endpoints.
type hostMetaLite struct {
	Title      string `json:"title,omitempty"`
	HasFavicon bool   `json:"has_favicon"`
}

// HostsHandler returns FQDNs exposed via Ingress, HTTPRoute, and
// IngressRoute. Reads from the host_exposure / exposed_digests
// materialised views (see 20260509_create_host_exposure_views.sql);
// freshness is ingest-driven via hostexposure.TriggerRefresh from the
// CallcenterHandler hook.
//
// Pagination via offset+limit. Default limit is 200; the frontend
// requests subsequent pages as the user scrolls so the wire payload
// per request stays bounded. The total count for "showing N of M" is
// served by HostSummaryHandler (no separate COUNT(*) round trip).
const (
	hostsDefaultLimit = 200
	hostsMaxLimit     = 500
)

func HostsHandler(db *gorm.DB, cs cache.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		activeOnly := r.URL.Query().Get("active_only") == "true"
		includeInactive := isTruthy(r.URL.Query().Get("include_inactive"))

		offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
		if offset < 0 {
			offset = 0
		}
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		if limit <= 0 {
			limit = hostsDefaultLimit
		}
		if limit > hostsMaxLimit {
			limit = hostsMaxLimit
		}
		// Free-text search and categorical filters all applied server-
		// side so pagination works correctly: the old client-side filters
		// only operated on rows already loaded, which gave wrong totals
		// and missed unloaded matches.
		searchQuery := strings.TrimSpace(r.URL.Query().Get("q"))
		filterClusters := parseHostFilterCSV(r.URL.Query().Get("cluster_ids"))
		filterNamespaces := parseHostFilterCSV(r.URL.Query().Get("namespaces"))
		filterKinds := parseHostFilterCSV(r.URL.Query().Get("kinds"))
		filterExposure := parseHostFilterCSV(r.URL.Query().Get("exposure"))
		activeWorkloadsOnly := isTruthy(r.URL.Query().Get("active_workloads_only"))
		sortColumn, sortDirection := parseHostSortParams(r.URL.Query().Get("sort"), r.URL.Query().Get("order"))

		rows := []HostRow{}
		ctx := r.Context()

		aclFrag, aclArgs, deny := clusterACLFilterCol(r, "he.cluster_id")
		if deny {
			writeJSON(w, http.StatusOK, rows)
			return
		}

		// Cold-start: the MVs are created WITH NO DATA. Refreshes run
		// asynchronously at boot (see main.go) and on every relevant
		// ingest. Until the first one lands, return an empty list
		// rather than a SQLSTATE 55000 — same pattern as triage.
		if ready, err := spamdb.HostExposureViewsPopulated(ctx, db); err != nil || !ready {
			writeJSON(w, http.StatusOK, rows)
			return
		}

		// Liveness gate. Live mode joins cluster_sessions and filters
		// out clusters whose agent has been silent past sessionLiveWindow.
		// include_inactive=true skips the join entirely and surfaces
		// every URL we've ever observed.
		livenessJoin := "JOIN cluster_sessions cs ON cs.cluster_id = he.cluster_id AND cs.last_push_at >= NOW() - " + liveWindowInterval()
		if includeInactive {
			livenessJoin = ""
		}

		aclWhere := ""
		if aclFrag != "" && aclFrag != "TRUE" {
			aclWhere = "AND " + aclFrag
		}

		filterWhere, filterArgs := buildHostFilterClauses(searchQuery, filterClusters, filterNamespaces, filterKinds)

		// Exposure filter rides on the hostresolve worker's DNS verdict
		// (host_resolution.classification) — the same source
		// computeHostSummary buckets by, so the table filter and the
		// summary chip counts always agree. The join is only added when
		// the filter is active so the unfiltered query plan is untouched.
		exposureWhere := buildHostExposureClause(filterExposure)
		exposureJoin := ""
		if exposureWhere != "" {
			exposureJoin = "LEFT JOIN host_resolution hr ON hr.host = he.host"
		}

		// workload_count is the count of distinct image digests that
		// sit on this URL's backend chain (see exposed_digests MV).
		// Better signal than the old EndpointSlice ready-address count
		// for triage UX: "how many running images are reachable here"
		// rather than "how many TCP endpoints reply" — and it lines up
		// directly with asset_risk's internet_exposed flag.
		query := `
			SELECT
			    he.host, he.kind, he.name, he.namespace, he.cluster, he.cluster_id,
			    he.environment, he.tls, he.lb_ips, he.ingress_class, he.backends,
			    COALESCE(w.cnt, 0) AS workload_count, he.last_seen
			FROM host_exposure he
			` + livenessJoin + `
			LEFT JOIN LATERAL (
			    SELECT COUNT(DISTINCT ed.digest)::bigint AS cnt
			    FROM exposed_digests ed
			    WHERE ed.cluster_id    = he.cluster_id
			      AND ed.namespace     = he.namespace
			      AND ed.host          = he.host
			      AND ed.exposure_kind = he.kind
			      AND ed.exposure_name = he.name
			) w ON TRUE
			` + exposureJoin + `
			WHERE TRUE ` + aclWhere + ` ` + filterWhere + ` ` + exposureWhere + `
			ORDER BY ` + sortColumn + ` ` + sortDirection + `, he.host ` + sortDirection + `, he.cluster ` + sortDirection + `
			LIMIT ? OFFSET ?
		`
		queryArgs := append([]any{}, aclArgs...)
		queryArgs = append(queryArgs, filterArgs...)
		queryArgs = append(queryArgs, limit, offset)

		if err := db.Raw(query, queryArgs...).Scan(&rows).Error; err != nil {
			log.Printf("HostsHandler query error: %v", err)
			http.Error(w, "query failed", http.StatusInternalServerError)
			return
		}

		// activeOnly (workload_count > 0) is post-paginate by design:
		// the workload_count is a per-row scalar, and the SQL only sees
		// it via the LATERAL subquery. Pushing it into the WHERE would
		// require materialising the count twice. Apply in Go on the
		// already-bounded page — cheap, and the page already paid for
		// the rows. activeWorkloadsOnly is a sibling for the host-tab
		// filter that hides cluster-side endpoints without running
		// containers; activeOnly is the older URL flag for the same
		// semantics, kept for backward compatibility.
		if activeWorkloadsOnly {
			activeOnly = true
		}

		writeAndFilterHosts(w, rows, cs, ctx, activeOnly)
	}
}

// imageSortColumnSQL maps the frontend's ImageDetail sort keys to
// columns available on the inventory_with_vulns CTE in
// ImageDetailHandler. 'vulns' resolves to a severity-weighted sum
// (vuln_weight) that mirrors the frontend's old vulnSortKey, so
// header-click sort by Vulns spans the whole dataset and not just
// the loaded page.
var imageSortColumnSQL = map[string]string{
	"registry":        "registry",
	"image":           "image",
	"digest":          "digest",
	"tags":            "tags",
	"cluster_count":   "cluster_count",
	"namespace_count": "namespace_count",
	"container_count": "container_count",
	"last_seen":       "last_seen",
	"vulns":           "vuln_weight",
}

// parseImageSortParams validates the sort + order params and returns
// the SQL column expression + direction. The default is
// (container_count DESC) — the previous unconfigurable behaviour, so
// the unfiltered first-page load keeps its old order.
func parseImageSortParams(rawSort, rawOrder string) (string, string) {
	column, ok := imageSortColumnSQL[strings.TrimSpace(strings.ToLower(rawSort))]
	if !ok {
		column = "container_count"
	}
	direction := "DESC"
	if strings.EqualFold(strings.TrimSpace(rawOrder), "asc") {
		direction = "ASC"
	}
	return column, direction
}

// hostSortColumnSQL maps the frontend's HostRow field names to SQL
// expressions over the host_exposure MV plus the LATERAL workload
// count. Anything not in this map falls back to (host, cluster) —
// the original ORDER BY before sort was added.
var hostSortColumnSQL = map[string]string{
	"host":           "he.host",
	"cluster":        "he.cluster",
	"cluster_id":     "he.cluster_id",
	"namespace":      "he.namespace",
	"name":           "he.name",
	"kind":           "he.kind",
	"environment":    "he.environment",
	"ingress_class":  "he.ingress_class",
	"workload_count": "COALESCE(w.cnt, 0)",
	"last_seen":      "he.last_seen",
}

// parseHostSortParams returns the SQL ORDER BY column expression and
// direction for the host list, validating both against allowlists so
// the user-supplied params never reach the SQL string directly. The
// fallback (host, asc) matches the pre-sort behaviour.
func parseHostSortParams(rawSort, rawOrder string) (string, string) {
	column, ok := hostSortColumnSQL[strings.TrimSpace(strings.ToLower(rawSort))]
	if !ok {
		column = "he.host"
	}
	direction := "ASC"
	if strings.EqualFold(strings.TrimSpace(rawOrder), "desc") {
		direction = "DESC"
	}
	return column, direction
}

// parseHostFilterCSV splits a comma-separated query-string value into
// trimmed non-empty tokens. nil result means "no filter applied".
func parseHostFilterCSV(raw string) []string {
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if v := strings.TrimSpace(p); v != "" {
			out = append(out, v)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// buildHostFilterClauses produces the WHERE fragment + args for the
// host_exposure search box and the cluster / namespace / kind
// multiselects. Shared between HostsHandler and HostSummaryHandler so
// the chip counts always reflect the same row set as the table.
func buildHostFilterClauses(searchQuery string, clusterIDs, namespaces, kinds []string) (string, []any) {
	var parts []string
	var args []any
	if searchQuery != "" {
		pattern := "%" + searchQuery + "%"
		parts = append(parts, `(
			he.host ILIKE ?
			OR he.cluster ILIKE ?
			OR he.namespace ILIKE ?
			OR he.name ILIKE ?
			OR he.environment ILIKE ?
			OR he.kind ILIKE ?
			OR he.ingress_class ILIKE ?
			OR he.backends ILIKE ?
			OR he.lb_ips ILIKE ?
		)`)
		for i := 0; i < 9; i++ {
			args = append(args, pattern)
		}
	}
	if len(clusterIDs) > 0 {
		placeholders := strings.TrimRight(strings.Repeat("?,", len(clusterIDs)), ",")
		parts = append(parts, `(he.cluster_id IN (`+placeholders+`) OR he.cluster IN (`+placeholders+`))`)
		for _, v := range clusterIDs {
			args = append(args, v)
		}
		for _, v := range clusterIDs {
			args = append(args, v)
		}
	}
	if len(namespaces) > 0 {
		placeholders := strings.TrimRight(strings.Repeat("?,", len(namespaces)), ",")
		parts = append(parts, `he.namespace IN (`+placeholders+`)`)
		for _, v := range namespaces {
			args = append(args, v)
		}
	}
	if len(kinds) > 0 {
		placeholders := strings.TrimRight(strings.Repeat("?,", len(kinds)), ",")
		parts = append(parts, `he.kind IN (`+placeholders+`)`)
		for _, v := range kinds {
			args = append(args, v)
		}
	}
	if len(parts) == 0 {
		return "", nil
	}
	return "AND " + strings.Join(parts, " AND "), args
}

// buildHostExposureClause maps the ?exposure= CSV onto the hostresolve
// worker's classification column (requires the host_resolution join to
// be in place). Allowlisted values: external, internal, pending —
// anything else is dropped. "pending" matches every host not classified
// internal/external (never resolved, or unresolvable), mirroring
// computeHostSummary's pending bucket so the filtered table lines up
// with the chip counts. All values are emitted as SQL literals from the
// allowlist, never from user input. Empty result means no filter.
func buildHostExposureClause(exposures []string) string {
	var parts []string
	for _, e := range exposures {
		switch strings.ToLower(strings.TrimSpace(e)) {
		case "external":
			parts = append(parts, "hr.classification = 'external'")
		case "internal":
			parts = append(parts, "hr.classification = 'internal'")
		case "pending":
			parts = append(parts, "COALESCE(hr.classification, 'pending') NOT IN ('internal', 'external')")
		}
	}
	if len(parts) == 0 {
		return ""
	}
	return "AND (" + strings.Join(parts, " OR ") + ")"
}

// HostSummary is the small response shape backing the cluster page's
// exposure chip. The page used to slice these counts client-side off
// the full /api/clusters/hosts payload — that meant ~1MB on the wire
// just to render four numbers, and "pending" included every host
// that hadn't entered the virtual-scroll viewport yet (because each
// host's DNS resolution was lazy-loaded only when visible).
//
// Server-side aggregation fixes both: tiny payload, and `Pending`
// genuinely means "no cached resolution and no LB IP to classify by",
// which is the only honest definition of unknown.
type HostSummary struct {
	External int `json:"external"`
	Internal int `json:"internal"`
	Pending  int `json:"pending"`
	Total    int `json:"total"`
	// Distinct values for the filter dropdowns. Computed in the same
	// query as the categorisation so the frontend doesn't have to do a
	// separate facets round-trip. Returned for the entire ACL-scoped
	// dataset, not the paginated table page — that's the whole point.
	Clusters   []HostFacetOption `json:"clusters"`
	Namespaces []string          `json:"namespaces"`
	Kinds      []string          `json:"kinds"`
}

// HostFacetOption pairs a cluster id with its display name so the
// multiselect can show "prod-eu-1" while the URL param carries the
// stable id.
type HostFacetOption struct {
	ID    string `json:"id"`
	Label string `json:"label"`
}

const hostSummaryCacheKeyPrefix = "hosts:summary:v1:"
const hostSummaryCacheTTL = 30 * time.Minute

type hostSummaryCacheEntry struct {
	Watermark time.Time   `json:"watermark"`
	Summary   HostSummary `json:"summary"`
}

// HostSummaryHandler returns aggregate exposure counts for the hosts
// the caller is allowed to see. The endpoint is meant for the cluster
// overview chip / donut — it is NOT a substitute for the full hosts
// list, just the summary numbers.
//
// Categorisation comes from host_resolution, written by the
// internal/hostresolve worker (see hostresolve.Classify for the full
// precedence). In short: a host-specific public-DNS answer (DoH, since
// outbound :53 is blocked) wins — under split-DNS only the public
// vantage can prove external exposure; otherwise the split-horizon
// resolver's answer, then the cluster-reported LoadBalancer IP.
// internal means RFC1918/loopback plus any operator-owned ranges in
// SPAM_HOST_INTERNAL_CIDRS; pending means no usable answer yet.
//
// Cached in kv_store keyed on the ACL fragment + the host_exposure MV
// watermark, so the cache invalidates naturally on the next MV refresh.
func HostSummaryHandler(db *gorm.DB, cs cache.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		includeInactive := isTruthy(r.URL.Query().Get("include_inactive"))

		aclFrag, aclArgs, deny := clusterACLFilterCol(r, "he.cluster_id")
		if deny {
			writeJSON(w, http.StatusOK, HostSummary{})
			return
		}

		// Same cold-start guard as the full list — return zeros rather
		// than 5xx while the MVs are still WITH NO DATA.
		if ready, err := spamdb.HostExposureViewsPopulated(ctx, db); err != nil || !ready {
			writeJSON(w, http.StatusOK, HostSummary{})
			return
		}

		// Same filters as HostsHandler so the chip totals correspond
		// 1:1 with what the table is currently showing. Skips the
		// summary cache when filters are applied (each unique filter
		// combination would otherwise spawn its own cache entry and
		// the kv_store would balloon for marginal benefit).
		searchQuery := strings.TrimSpace(r.URL.Query().Get("q"))
		filterClusters := parseHostFilterCSV(r.URL.Query().Get("cluster_ids"))
		filterNamespaces := parseHostFilterCSV(r.URL.Query().Get("namespaces"))
		filterKinds := parseHostFilterCSV(r.URL.Query().Get("kinds"))
		filterWhere, filterArgs := buildHostFilterClauses(searchQuery, filterClusters, filterNamespaces, filterKinds)
		filtersApplied := filterWhere != ""

		watermark := hostExposureWatermark(ctx, db)
		var cacheKey string
		if !filtersApplied {
			cacheKey = buildHostSummaryCacheKey(aclFrag, aclArgs, includeInactive)
			if entry, ok, _ := cache.GetJSON[hostSummaryCacheEntry](ctx, cs, cacheKey); ok {
				if !watermark.IsZero() && !entry.Watermark.Before(watermark) {
					writeJSON(w, http.StatusOK, entry.Summary)
					return
				}
			}
		}

		summary, err := computeHostSummary(ctx, db, cs, aclFrag, aclArgs, includeInactive, filterWhere, filterArgs)
		if err != nil {
			http.Error(w, "query failed", http.StatusInternalServerError)
			return
		}

		// Cascading-filter facets: each dropdown's options come from a
		// scan that EXCLUDES that dropdown's own selection from the
		// filter. So picking one cluster doesn't collapse the cluster
		// list — the user can still add another cluster without
		// clearing first.
		clusters, namespaces, kinds, ferr := hostFacets(ctx, db, aclFrag, aclArgs, includeInactive, searchQuery, filterClusters, filterNamespaces, filterKinds)
		if ferr != nil {
			http.Error(w, "facet query failed", http.StatusInternalServerError)
			return
		}
		summary.Clusters = clusters
		summary.Namespaces = namespaces
		summary.Kinds = kinds

		if !filtersApplied && cache.ShouldStore(ctx) {
			_ = cache.SetJSON(ctx, cs, cacheKey, hostSummaryCacheEntry{
				Watermark: watermark,
				Summary:   summary,
			}, hostSummaryCacheTTL)
		}

		writeJSON(w, http.StatusOK, summary)
	}
}

func hostExposureWatermark(ctx context.Context, db *gorm.DB) time.Time {
	var refreshedAt time.Time
	db.WithContext(ctx).Raw(
		"SELECT refreshed_at FROM materialized_view_refreshes WHERE name = 'host_exposure' LIMIT 1",
	).Scan(&refreshedAt)
	return refreshedAt
}

func buildHostSummaryCacheKey(aclFrag string, aclArgs []any, includeInactive bool) string {
	h := fnv.New64a()
	enc := json.NewEncoder(h)
	_ = enc.Encode(struct {
		Frag            string
		Args            []any
		IncludeInactive bool
		Resolver        string
		InternalCIDRs   []string
	}{aclFrag, aclArgs, includeInactive, hostDNSResolverAddr, hostInternalCIDRStrings()})
	return fmt.Sprintf("%s%x", hostSummaryCacheKeyPrefix, h.Sum64())
}

// computeHostSummary aggregates the deduped host set the caller can see
// into internal/external/pending counts. Classification comes from
// host_resolution, which is kept up to date off the request path by
// internal/hostresolve.Worker — so this function is pure SQL and
// answers in milliseconds even on multi-thousand-host fleets. A host
// that the worker hasn't reached yet shows up as "pending", same as a
// host whose DNS lookup has failed and has no LB IP fallback.
func computeHostSummary(ctx context.Context, db *gorm.DB, _ cache.Store, aclFrag string, aclArgs []any, includeInactive bool, filterWhere string, filterArgs []any) (HostSummary, error) {
	livenessJoin := "JOIN cluster_sessions cs ON cs.cluster_id = he.cluster_id AND cs.last_push_at >= NOW() - " + liveWindowInterval()
	if includeInactive {
		livenessJoin = ""
	}
	aclWhere := ""
	if aclFrag != "" && aclFrag != "TRUE" {
		aclWhere = "AND " + aclFrag
	}

	type aggRow struct {
		Total    int `gorm:"column:total"`
		Internal int `gorm:"column:internal"`
		External int `gorm:"column:external"`
		Pending  int `gorm:"column:pending"`
	}
	var agg aggRow
	query := `
		SELECT
		  COUNT(DISTINCT he.host)                                                                  AS total,
		  COUNT(DISTINCT he.host) FILTER (WHERE hr.classification = 'internal')                    AS internal,
		  COUNT(DISTINCT he.host) FILTER (WHERE hr.classification = 'external')                    AS external,
		  COUNT(DISTINCT he.host) FILTER (WHERE COALESCE(hr.classification, 'pending')
		                                          NOT IN ('internal', 'external'))                 AS pending
		FROM host_exposure he
		` + livenessJoin + `
		LEFT JOIN host_resolution hr ON hr.host = he.host
		WHERE TRUE ` + aclWhere + ` ` + filterWhere
	queryArgs := append([]any{}, aclArgs...)
	queryArgs = append(queryArgs, filterArgs...)
	if err := db.WithContext(ctx).Raw(query, queryArgs...).Scan(&agg).Error; err != nil {
		return HostSummary{}, err
	}
	return HostSummary{
		Total:    agg.Total,
		Internal: agg.Internal,
		External: agg.External,
		Pending:  agg.Pending,
	}, nil
}

// hostFacets returns the dropdown options for cluster / namespace /
// kind multiselects with cascading-filter semantics: each dropdown's
// options exclude that dropdown's *own* selection from the filter
// scope so the user can extend the selection without having to clear
// it first. Cluster dropdown shows all clusters even when one is
// already selected; namespace dropdown shows namespaces present in
// the currently-selected clusters (cluster filter still applied); etc.
//
// Three queries because each dropdown needs a different filter scope.
// They're all DISTINCT scans over the host_exposure MV; cheap in
// practice (a few thousand rows max for typical fleets).
func hostFacets(ctx context.Context, db *gorm.DB, aclFrag string, aclArgs []any, includeInactive bool, searchQuery string, filterClusters, filterNamespaces, filterKinds []string) (clusters []HostFacetOption, namespaces []string, kinds []string, err error) {
	livenessJoin := "JOIN cluster_sessions cs ON cs.cluster_id = he.cluster_id AND cs.last_push_at >= NOW() - " + liveWindowInterval()
	if includeInactive {
		livenessJoin = ""
	}
	aclWhere := ""
	if aclFrag != "" && aclFrag != "TRUE" {
		aclWhere = "AND " + aclFrag
	}

	// Cluster facets: ignore cluster filter, apply the rest.
	clusterWhere, clusterArgs := buildHostFilterClauses(searchQuery, nil, filterNamespaces, filterKinds)
	type clusterRow struct {
		ClusterID string `gorm:"column:cluster_id"`
		Cluster   string `gorm:"column:cluster"`
	}
	var clusterRows []clusterRow
	clusterQuery := `
		SELECT DISTINCT he.cluster_id, he.cluster
		FROM host_exposure he
		` + livenessJoin + `
		WHERE TRUE ` + aclWhere + ` ` + clusterWhere + ` AND he.cluster_id <> ''
		ORDER BY he.cluster
	`
	cArgs := append([]any{}, aclArgs...)
	cArgs = append(cArgs, clusterArgs...)
	if err = db.WithContext(ctx).Raw(clusterQuery, cArgs...).Scan(&clusterRows).Error; err != nil {
		return nil, nil, nil, err
	}
	clusters = make([]HostFacetOption, 0, len(clusterRows))
	for _, r := range clusterRows {
		label := r.Cluster
		if label == "" {
			label = r.ClusterID
		}
		clusters = append(clusters, HostFacetOption{ID: r.ClusterID, Label: label})
	}

	// Namespace facets: ignore namespace filter, apply the rest.
	nsWhere, nsArgs := buildHostFilterClauses(searchQuery, filterClusters, nil, filterKinds)
	nsQuery := `
		SELECT DISTINCT he.namespace
		FROM host_exposure he
		` + livenessJoin + `
		WHERE TRUE ` + aclWhere + ` ` + nsWhere + ` AND he.namespace <> ''
		ORDER BY he.namespace
	`
	nArgs := append([]any{}, aclArgs...)
	nArgs = append(nArgs, nsArgs...)
	if err = db.WithContext(ctx).Raw(nsQuery, nArgs...).Scan(&namespaces).Error; err != nil {
		return nil, nil, nil, err
	}

	// Kind facets: ignore kind filter, apply the rest.
	kindWhere, kindArgs := buildHostFilterClauses(searchQuery, filterClusters, filterNamespaces, nil)
	kindQuery := `
		SELECT DISTINCT he.kind
		FROM host_exposure he
		` + livenessJoin + `
		WHERE TRUE ` + aclWhere + ` ` + kindWhere + ` AND he.kind <> ''
		ORDER BY he.kind
	`
	kArgs := append([]any{}, aclArgs...)
	kArgs = append(kArgs, kindArgs...)
	if err = db.WithContext(ctx).Raw(kindQuery, kArgs...).Scan(&kinds).Error; err != nil {
		return nil, nil, nil, err
	}

	return clusters, namespaces, kinds, nil
}

// writeAndFilterHosts applies the activeOnly filter, inlines resolve +
// meta from their per-host caches (nil on miss — frontend falls back),
// and writes the response. Kept separate so cache-hit and cache-miss
// paths share identical output logic.
func writeAndFilterHosts(w http.ResponseWriter, rows []HostRow, cs cache.Store, ctx context.Context, activeOnly bool) {
	if activeOnly {
		filtered := rows[:0]
		for _, row := range rows {
			if row.WorkloadCount > 0 {
				filtered = append(filtered, row)
			}
		}
		rows = filtered
	}

	// Inline resolve + meta at serialize time. Deduplicate lookups
	// per host since the same FQDN appears once per cluster/namespace
	// (e.g. shared *.apps wildcard rolled out to every cluster).
	type hostCaches struct {
		resolved *resolveResult
		meta     *hostMetaLite
	}
	seen := make(map[string]hostCaches, len(rows))
	for i := range rows {
		host := rows[i].Host
		hc, ok := seen[host]
		if !ok {
			if res, found, _ := cache.GetJSON[resolveResult](ctx, cs, resolveCacheKey(host)); found {
				r := res
				hc.resolved = &r
			}
			if m, found, _ := cache.GetJSON[hostMeta](ctx, cs, metaCachePrefix+host); found {
				hc.meta = &hostMetaLite{Title: m.Title, HasFavicon: m.HasFavicon}
			}
			seen[host] = hc
		}
		rows[i].Resolved = hc.resolved
		rows[i].Meta = hc.meta
	}

	writeJSON(w, http.StatusOK, rows)
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
		if ok, err := canReadCluster(r, db, clusterID); err != nil || !ok {
			// Return the same shape as a missing cluster — never leak
			// existence via differential error messages.
			http.Error(w, "not found", http.StatusNotFound)
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
			Namespace    string `json:"namespace"`
			Name         string `json:"name"`
			ServiceType  string `json:"service_type"`
			PortsJSON    string `gorm:"column:ports_json"`
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

		// Step 1: All ingresses/routes in this cluster. liveCTEForCluster
		// pre-filters by cluster_id so the per-branch cluster_id checks
		// become no-ops we drop.
		var ingresses []nsIngress
		db.Raw(liveCTEForCluster+`
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
				  AND jsonb_typeof(data->'hosts') = 'array'
				UNION ALL
				SELECT
					data->>'namespace' AS namespace,
					h AS host,
					data->>'kind' AS kind,
					data->>'name' AS name,
					'' AS ingress_class,
					FALSE AS tls,
					CASE WHEN jsonb_typeof(data->'backends') = 'array'
						THEN COALESCE(
							(SELECT string_agg(DISTINCT b->>'name', ', ')
							 FROM jsonb_array_elements(data->'backends') AS b), '')
						ELSE '' END AS backends
				FROM live,
				     jsonb_array_elements_text(data->'hostnames') AS h
				WHERE data->>'kind' IN ('HTTPRoute','GRPCRoute','TLSRoute')
				  AND jsonb_typeof(data->'hostnames') = 'array'
			) sub WHERE host IS NOT NULL AND host != ''
			ORDER BY namespace, host
		`, clusterID).Scan(&ingresses)

		// Step 2: All services in this cluster
		var services []nsSvc
		db.Raw(liveCTEForCluster+`
			SELECT
				data->>'namespace' AS namespace,
				data->>'name' AS name,
				COALESCE(data->>'service_type', '') AS service_type,
				COALESCE(data->'ports'::text, '[]') AS ports_json,
				COALESCE(data->'selector'::text, '{}') AS selector_json
			FROM live
			WHERE data->>'kind' = 'Service'
			ORDER BY data->>'namespace', data->>'name'
		`, clusterID).Scan(&services)

		// Step 3: All running pod groups in this cluster
		var pods []nsPod
		db.Raw(liveCTEForCluster+`
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
			Namespace string          `json:"namespace"`
			Ingresses []chainIng      `json:"ingresses"`
			Services  []chainSvc      `json:"services"`
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
		db.Raw(liveCTEForCluster+`
			SELECT
				data->>'namespace' AS namespace,
				data->>'service_name' AS service_name,
				jsonb_array_elements_text(
					jsonb_array_elements(data->'endpoints')->'addresses'
				) AS address
			FROM live
			WHERE data->>'kind' = 'EndpointSlice'
		`, clusterID).Scan(&epIPs)

		// Endpoint ports per service
		type epPortRow struct {
			Namespace   string `json:"namespace"`
			ServiceName string `gorm:"column:service_name"`
			Port        int    `gorm:"column:port"`
		}
		var epPortRows []epPortRow
		db.Raw(liveCTEForCluster+`
			SELECT DISTINCT
				data->>'namespace' AS namespace,
				data->>'service_name' AS service_name,
				(p->>'port')::int AS port
			FROM live, jsonb_array_elements(data->'ports') AS p
			WHERE data->>'kind' = 'EndpointSlice'
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

		// Resolve cluster name through clusters table — the per-record
		// `data->>'cluster'` may carry the kube-system UID on agents
		// emitting the new identity scheme, so go through the ROR
		// binding written by upsertClusterRorBinding instead.
		var clusterName string
		db.Raw(`SELECT COALESCE(NULLIF(ror_cluster_name,''), NULLIF(ror_slug,''), cluster_id) FROM clusters WHERE cluster_id = ? LIMIT 1`, clusterID).Scan(&clusterName)
		if clusterName == "" {
			clusterName = clusterID
		}

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
		if ok, err := canReadCluster(r, db, clusterID); err != nil || !ok {
			http.Error(w, "not found", http.StatusNotFound)
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
			Name          string            `json:"name"`
			Namespace     string            `json:"namespace"`
			ServiceType   string            `json:"service_type"`
			Ports         []chainPort       `json:"ports"`
			Selector      map[string]string `json:"selector"`
			PodCount      int64             `json:"pod_count"`
			EndpointIPs   []string          `json:"endpoint_ips,omitempty"`
			EndpointPorts []int             `json:"endpoint_ports,omitempty"`
		}
		type chainContainer struct {
			Name     string `json:"name"`
			Image    string `json:"image"`
			Tag      string `json:"tag"`
			Digest   string `json:"digest,omitempty"`
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
			Cluster   string          `json:"cluster"`
			ClusterID string          `json:"cluster_id"`
			Namespace string          `json:"namespace"`
			Ingress   *chainIngress   `json:"ingress"`
			Services  []chainService  `json:"services"`
			Pods      []chainPodGroup `json:"pods"`
		}

		// Resolve cluster name through clusters table — see the matching
		// note in ClusterChainHandler. data->>'cluster' carries whatever
		// SCAM stamped at ingest, which is the UID under the new
		// identity scheme.
		var clusterName string
		db.Raw(`SELECT COALESCE(NULLIF(ror_cluster_name,''), NULLIF(ror_slug,''), cluster_id) FROM clusters WHERE cluster_id = ? LIMIT 1`, clusterID).Scan(&clusterName)
		if clusterName == "" {
			clusterName = clusterID
		}

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
		// liveCTEForCluster narrows the dedup CTE to one cluster up
		// front — at fleet scale the full-fleet liveCTE timed this
		// endpoint out because DISTINCT ON had to scan every cluster's
		// records before the trailing WHERE could filter by cluster_id.
		// Per-cluster narrow turns sub-second; same change applies to
		// the service and pod queries below.
		err := db.Raw(liveCTEForCluster+`
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
					CASE WHEN jsonb_typeof(data->'backends') = 'array'
						THEN COALESCE(
							(SELECT string_agg(DISTINCT b->>'name', ', ')
							 FROM jsonb_array_elements(data->'backends') AS b), '')
						ELSE '' END AS backends,
					'[]' AS paths_json
				FROM live
				WHERE data->>'kind' IN ('HTTPRoute', 'GRPCRoute', 'TLSRoute')
				  AND data->>'namespace' = ?
				  AND jsonb_typeof(data->'hostnames') = 'array'
				  AND ? = ANY(
				    SELECT jsonb_array_elements_text(data->'hostnames')
				  )
			) sub LIMIT 1
		`, clusterID, host, host, namespace, host,
			namespace, host,
			namespace, host,
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
				Name         string `json:"name"`
				Namespace    string `json:"namespace"`
				ServiceType  string `json:"service_type"`
				PortsJSON    string `gorm:"column:ports_json"`
				SelectorJSON string `gorm:"column:selector_json"`
			}
			var svcRows []svcRow
			err = db.Raw(liveCTEForCluster+`
				SELECT
					data->>'name' AS name,
					data->>'namespace' AS namespace,
					COALESCE(data->>'service_type', '') AS service_type,
					COALESCE(data->'ports'::text, '[]') AS ports_json,
					COALESCE(data->'selector'::text, '{}') AS selector_json
				FROM live
				WHERE data->>'kind' = 'Service'
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
					err = db.Raw(liveCTEForCluster+`
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
			db.Raw(liveCTEForCluster+`
				SELECT DISTINCT
					s.data->>'name' AS name,
					s.data->>'namespace' AS namespace,
					COALESCE(s.data->>'service_type', '') AS service_type,
					COALESCE(s.data->'ports'::text, '[]') AS ports_json,
					COALESCE(s.data->'selector'::text, '{}') AS selector_json
				FROM live s, live c
				WHERE s.data->>'kind' = 'Service'
				  AND s.data->>'namespace' = ?
				  AND s.data->>'service_type' IN ('LoadBalancer', 'NodePort')
				  AND c.data->>'kind' = 'Container'
				  AND c.data->>'pod_phase' = 'Running'
				  AND c.data->>'namespace' = ?
				  AND jsonb_typeof(s.data->'selector') = 'object'
				  AND (c.data->'pod_labels') @> (s.data->'selector')
				  AND c.data->>'owner' IN (?)
			`, clusterID, namespace, namespace,
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

// resolveResult is the DNS lookup shape cached under resolveCachePrefix
// and inlined into HostsHandler's list response. Kept package-level so
// both the standalone handler and the list aggregator share one type.
type resolveResult struct {
	Host    string   `json:"host"`
	IPs     []string `json:"ips"`
	IsLocal bool     `json:"is_local"`
	Error   string   `json:"error,omitempty"`
}

// resolveCachePrefix / resolveTTL gate the DNS lookup cache. 24h TTL
// matches hostmeta: for operator-facing infra hosts (ingress/routes),
// DNS changes on cluster reconfigs — days to weeks, not minutes. The
// old 1h value produced a live lookup per host per hour of page use
// with no actual freshness win.
const (
	resolveCachePrefix = "resolve:"
	resolveTTL         = 24 * time.Hour
)

var (
	hostDNSResolverAddr = resolveHostDNSResolverAddr()
	hostDNSResolver     = newHostDNSResolver(hostDNSResolverAddr)
	hostInternalCIDRs   = parseHostInternalCIDRs()
)

// resolveHostDNSResolverAddr returns the operator-configured DNS server,
// or "" for the system resolver. The system default matters: it knows
// split-horizon internal zones, while a hardcoded public resolver can
// never resolve internal-only hosts (and outbound :53 to the internet is
// blocked in most of our environments), which left every host
// unresolvable and the internal/external split empty.
func resolveHostDNSResolverAddr() string {
	raw := strings.TrimSpace(os.Getenv("SPAM_HOST_DNS_RESOLVER"))
	if raw == "" {
		return ""
	}
	if _, _, err := net.SplitHostPort(raw); err == nil {
		return raw
	}
	return net.JoinHostPort(raw, "53")
}

func newHostDNSResolver(addr string) *net.Resolver {
	if addr == "" {
		return net.DefaultResolver
	}
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: 3 * time.Second}
			return d.DialContext(ctx, network, addr)
		},
	}
}

func resolveCacheKey(host string) string {
	h := fnv.New64a()
	_, _ = h.Write([]byte(hostDNSResolverAddr))
	for _, cidr := range hostInternalCIDRs {
		_, _ = h.Write([]byte(cidr.String()))
	}
	return fmt.Sprintf("%s%x:%s", resolveCachePrefix, h.Sum64(), host)
}

func parseHostInternalCIDRs() []*net.IPNet {
	raw := strings.TrimSpace(os.Getenv("SPAM_HOST_INTERNAL_CIDRS"))
	if raw == "" {
		return nil
	}
	var out []*net.IPNet
	for _, entry := range strings.Split(raw, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		_, cidr, err := net.ParseCIDR(entry)
		if err != nil {
			log.Printf("scam: ignoring invalid SPAM_HOST_INTERNAL_CIDRS entry %q: %v", entry, err)
			continue
		}
		out = append(out, cidr)
	}
	return out
}

func hostInternalCIDRStrings() []string {
	if len(hostInternalCIDRs) == 0 {
		return nil
	}
	out := make([]string, 0, len(hostInternalCIDRs))
	for _, cidr := range hostInternalCIDRs {
		out = append(out, cidr.String())
	}
	return out
}

func resolveHost(ctx context.Context, cs cache.Store, host string) resolveResult {
	cacheKey := resolveCacheKey(host)
	if cached, ok, _ := cache.GetJSON[resolveResult](ctx, cs, cacheKey); ok {
		return cached
	}

	lookupCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	ips, err := hostDNSResolver.LookupHost(lookupCtx, host)
	if err != nil {
		res := resolveResult{Host: host, Error: "unresolvable"}
		_ = cache.SetJSON(ctx, cs, cacheKey, res, resolveTTL)
		return res
	}

	// Internal iff every resolved address is private: answer order is
	// nondeterministic (round-robin, mixed A/AAAA), and any public
	// address means the host is reachable from outside.
	local := len(ips) > 0
	for _, ip := range ips {
		if !isPrivateIP(ip) {
			local = false
			break
		}
	}

	res := resolveResult{Host: host, IPs: ips, IsLocal: local}
	_ = cache.SetJSON(ctx, cs, cacheKey, res, resolveTTL)
	return res
}

// ResolveHostHandler does a DNS lookup for a given host and returns the IPs.
// Used as a per-host fallback when HostsHandler's list response ships
// without an inline resolve entry (first time a host is seen after
// ingest; HostsHandler's cache lookup missed). A successful fallback
// populates the cache so the next list response picks it up for free.
func ResolveHostHandler(cs cache.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		host := r.URL.Query().Get("host")
		if host == "" {
			http.Error(w, "missing host parameter", http.StatusBadRequest)
			return
		}

		ctx := r.Context()
		writeJSON(w, http.StatusOK, resolveHost(ctx, cs, host))
	}
}

// isPrivateIP returns true when ipStr falls in RFC1918, RFC4193 (IPv6
// ULA), loopback, link-local, or any operator-configured
// SPAM_HOST_INTERNAL_CIDRS range.
func isPrivateIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return true
	}
	for _, cidr := range hostInternalCIDRs {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

type ingestResponse struct {
	Accepted        int   `json:"accepted"`
	Snapshots       int   `json:"snapshots,omitempty"`
	Rejected        int   `json:"rejected,omitempty"`
	LastSeenEventID int64 `json:"last_seen_event_id,omitempty"`
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}
