package scam

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"gorm.io/gorm"
)

// ClusterSession tracks per-cluster agent liveness. Read queries gate
// visibility of cluster_record rows on `last_push_at` being recent —
// i.e. the agent has heartbeated or pushed data within
// sessionLiveWindow. Heartbeats and data batches both bump
// `last_push_at` (see HeartbeatHandler and CallcenterHandler).
//
// `session_started_at` records when the cluster first reported in and
// is never advanced thereafter — we used to roll it forward on
// reconnect and gate reads on `received_at >= session_started_at`, but
// that wiped all known resources whenever the agent blipped because it
// doesn't reliably re-INITIAL. Kept as a diagnostic timestamp.
type ClusterSession struct {
	ClusterID        string    `gorm:"primaryKey;size:128;column:cluster_id"`
	SessionStartedAt time.Time `gorm:"not null;column:session_started_at"`
	LastPushAt       time.Time `gorm:"not null;index;column:last_push_at"`
	// LastSeenEventID is the highest agent-stamped event_id SPAM has
	// persisted for this cluster. Returned in the push response so
	// SCAM can detect drift vs. its local high-water mark. Resets to
	// 0 when a SCAM agent restarts because the agent restarts its
	// counter from 0 — any mismatch triggers SCAM to reconcile.
	LastSeenEventID int64 `gorm:"not null;default:0;column:last_seen_event_id"`
}

func (ClusterSession) TableName() string { return "cluster_sessions" }

// defaultSessionLiveWindow is how fresh last_push_at must be for the
// cluster to be considered "live" in the UI. 24h is intentionally
// generous: the SCAM agent doesn't currently emit heartbeats, so
// last_push_at only advances on actual resource changes. A stable
// cluster with no pod churn for several hours would otherwise fall
// outside a shorter window and disappear from the dashboard. Once
// the agent wires /api/scam/heartbeat this can drop back to ~1h.
// Override with SPAM_CLUSTER_LIVE_WINDOW (any Go duration, e.g. "6h",
// "48h").
const defaultSessionLiveWindow = 24 * time.Hour

// sessionLiveWindow is resolved once at package init from the env var.
// Plumbed into the SQL filters below via fmt.Sprintf so there's a
// single source of truth.
var sessionLiveWindow = resolveLiveWindow()

func resolveLiveWindow() time.Duration {
	raw := strings.TrimSpace(os.Getenv("SPAM_CLUSTER_LIVE_WINDOW"))
	if raw == "" {
		return defaultSessionLiveWindow
	}
	d, err := time.ParseDuration(raw)
	if err != nil || d <= 0 {
		log.Printf("scam: invalid SPAM_CLUSTER_LIVE_WINDOW=%q, using default %s", raw, defaultSessionLiveWindow)
		return defaultSessionLiveWindow
	}
	return d
}

// touchClusterSession records an incoming push for a cluster, bumping
// last_push_at to now. Called once per callcenter batch or heartbeat,
// scoped to the set of distinct cluster_ids in the batch.
//
// session_started_at is only set on the initial INSERT; subsequent
// pushes leave it frozen. We used to roll it forward on long silences,
// but nothing reads that anymore.
//
// The first time an agent reports a new cluster_id we also register
// it in the `clusters` table so it can be referenced by ACL grants.
// No grants are seeded — clusters are deny-by-default; an admin has
// to claim the cluster before non-admins can see it. Registration is
// idempotent via ON CONFLICT (cluster_id) DO NOTHING.
//
// Detaches from the caller's cancellation: agents close the connection
// the moment the ingest body has flushed, which raced the registration
// INSERT and produced "scam: register cluster <id>: context canceled"
// — leaving brand-new clusters absent from the `clusters` table and
// therefore unclaimable. Registration must outlive the request, so we
// run both writes against a detached context with a hard deadline.
// maxEventID is the highest event_id observed for clusterID in the
// current batch; 0 if no records carry one. GREATEST in the upsert
// guarantees the stored last_seen_event_id is monotonically
// non-decreasing within a session — except across a SCAM agent
// restart, when the agent's counter resets to 0 and SPAM's stored
// value becomes "ahead", which is the signal SCAM uses to fire a
// reconcile snapshot. Heartbeats pass maxEventID=0 (no records, no
// change).
func touchClusterSession(ctx context.Context, db *gorm.DB, clusterID string, now time.Time, maxEventID int64) error {
	bg, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	if err := db.WithContext(bg).Exec(`
		INSERT INTO clusters (id, cluster_id, display_name, first_seen_at, created_at)
		VALUES (gen_random_uuid()::text, ?, ?, ?, ?)
		ON CONFLICT (cluster_id) DO NOTHING
	`, clusterID, clusterID, now, now).Error; err != nil {
		// Registration failure must not block liveness tracking —
		// the row will be auto-registered on the next heartbeat.
		log.Printf("scam: register cluster %s: %v", clusterID, err)
	}
	return db.WithContext(bg).Exec(`
		INSERT INTO cluster_sessions (cluster_id, session_started_at, last_push_at, last_seen_event_id)
		VALUES (?, ?, ?, ?)
		ON CONFLICT (cluster_id) DO UPDATE SET
		  last_push_at = EXCLUDED.last_push_at,
		  last_seen_event_id = GREATEST(cluster_sessions.last_seen_event_id, EXCLUDED.last_seen_event_id)
	`, clusterID, now, now, maxEventID).Error
}

// upsertClusterRorBinding writes the ROR-side identifiers (slug, name,
// environment) onto the cluster's row. SCAM emits these in a nested
// `ror_metadata` object once a cluster has resolved its ROR identity;
// SPAM keys everything on the top-level cluster_id (kube-system UID),
// but stores the binding here so the ACL filter can resolve ROR-sourced
// grants — which speak slug — back to the kube-system UID used as the
// join key throughout the rest of the schema.
//
// Idempotent: callers may invoke this on every batch; the IS DISTINCT
// FROM guard avoids a write when nothing has changed. Detaches from the
// request context the same way touchClusterSession does, so the write
// outlives an agent that hangs up the moment ingest acks.
//
// Atomic slug handoff: the partial unique index ux_clusters_ror_slug
// allows at most one row per non-empty slug. During SCAM's identity
// cutover the same slug previously sat on the pre-cutover slug-keyed
// clusters row and now needs to migrate to the new UID-keyed row. The
// transaction clears the slug from any other row first, then claims it
// on this row — so ACL evaluations against ror_slug always see the
// current cluster binding, never a stale one stuck on an obsolete
// cluster_id.
func upsertClusterRorBinding(ctx context.Context, db *gorm.DB, clusterID string, m *RorMetadata) {
	if m == nil || strings.TrimSpace(m.ClusterID) == "" {
		return
	}
	bg, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	err := db.WithContext(bg).Transaction(func(tx *gorm.DB) error {
		if err := tx.Exec(
			`UPDATE clusters SET ror_slug = '' WHERE ror_slug = ? AND cluster_id <> ?`,
			m.ClusterID, clusterID,
		).Error; err != nil {
			return err
		}
		return tx.Exec(`
			UPDATE clusters
			SET ror_slug = ?,
			    ror_cluster_name = ?,
			    ror_env = ?
			WHERE cluster_id = ?
			  AND (ror_slug, ror_cluster_name, ror_env) IS DISTINCT FROM (?, ?, ?)
		`,
			m.ClusterID, m.ClusterName, m.Env,
			clusterID,
			m.ClusterID, m.ClusterName, m.Env,
		).Error
	})
	if err != nil {
		log.Printf("scam: upsert ror binding cluster=%s slug=%s: %v", clusterID, m.ClusterID, err)
	}
}

// lookupLastSeenEventID returns the cluster's last_seen_event_id from
// cluster_sessions, or 0 if the cluster isn't yet registered. Used by
// CallcenterHandler to populate the ACK in the push response.
func lookupLastSeenEventID(ctx context.Context, db *gorm.DB, clusterID string) int64 {
	var v int64
	bg, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	_ = db.WithContext(bg).Raw(
		`SELECT last_seen_event_id FROM cluster_sessions WHERE cluster_id = ?`,
		clusterID,
	).Scan(&v).Error
	return v
}

// liveWindowInterval renders sessionLiveWindow as a PostgreSQL INTERVAL
// literal. Used by the SQL filters below so all read sites share a
// single configurable window.
func liveWindowInterval() string {
	return fmt.Sprintf("INTERVAL '%d seconds'", int64(sessionLiveWindow.Seconds()))
}

// LiveRecordFilter is the SQL fragment that a read query should append
// to its WHERE to see only rows belonging to a currently-live cluster.
// "Live" is heartbeat-driven: `last_push_at` is bumped by both data
// batches (CallcenterHandler) and keepalive pings (HeartbeatHandler),
// so a cluster that's alive but quiet on data still keeps its
// resources visible.
//
// We deliberately do NOT gate on `received_at >= session_started_at`.
// Doing so made every agent reconnect (API redeploy, network blip)
// hide all prior resources until the agent re-sent INITIAL for each —
// and the agent doesn't reliably re-snapshot. Liveness alone is the
// right invariant: if the agent is heartbeating, its reported state
// stands; explicit `msg='DELETE'` still prunes individual resources.
var LiveRecordFilter = ` AND EXISTS (
	SELECT 1 FROM cluster_sessions cs
	WHERE cs.cluster_id = data->>'cluster_id'
	  AND cs.last_push_at >= NOW() - ` + liveWindowInterval() + `
) `

// LiveRecordFilterAlias is the same predicate keyed off a table alias
// (e.g. `c.data`, `s.data`). Used in correlated subqueries where the
// bare column name would be ambiguous.
func LiveRecordFilterAlias(alias string) string {
	return ` AND EXISTS (
		SELECT 1 FROM cluster_sessions cs
		WHERE cs.cluster_id = ` + alias + `.data->>'cluster_id'
		  AND cs.last_push_at >= NOW() - ` + liveWindowInterval() + `
	) `
}
