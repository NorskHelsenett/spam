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
func touchClusterSession(ctx context.Context, db *gorm.DB, clusterID string, now time.Time) error {
	return db.WithContext(ctx).Exec(`
		INSERT INTO cluster_sessions (cluster_id, session_started_at, last_push_at)
		VALUES (?, ?, ?)
		ON CONFLICT (cluster_id) DO UPDATE SET
		  last_push_at = EXCLUDED.last_push_at
	`, clusterID, now, now).Error
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
