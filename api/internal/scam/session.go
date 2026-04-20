package scam

import (
	"context"
	"time"

	"gorm.io/gorm"
)

// ClusterSession tracks per-cluster agent activity so live-state read
// queries can distinguish "rows from the agent's current session" from
// "rows left over from a prior session that the agent can't see anymore".
//
// Flow:
//
//  1. Every callcenter batch upserts this row with last_push_at = now.
//  2. If the previous last_push_at is older than sessionIdleGap, the
//     agent was considered silent and is now reconnecting — session
//     rolls over (session_started_at = now). This is how we detect the
//     INITIAL-snapshot boundary without needing the agent to mark it.
//  3. Read queries JOIN on this table and filter
//     `cluster_record.received_at >= session_started_at AND last_push_at
//     recent`. Rows from prior sessions (however old) become stale the
//     instant the agent reconnects.
//
// Why not a time interval? Agents aren't obligated to heartbeat. A
// stable Ingress or Service might sit unchanged for weeks — the agent
// emits INITIAL once and never speaks of it again. An interval filter
// would hide those legitimate rows. Session tracking shows them
// correctly as long as the agent session is alive, and hides them
// the moment the agent reconnects (because the session boundary
// advances past their frozen received_at).
type ClusterSession struct {
	ClusterID        string    `gorm:"primaryKey;size:128;column:cluster_id"`
	SessionStartedAt time.Time `gorm:"not null;column:session_started_at"`
	LastPushAt       time.Time `gorm:"not null;index;column:last_push_at"`
}

func (ClusterSession) TableName() string { return "cluster_sessions" }

// sessionIdleGap is the quiet period after which the next incoming push
// is treated as a new agent session rather than an extension of the
// current one. Sized so the recommended 60s heartbeat cadence has
// comfortable margin — any jitter in the agent's ticker never
// accidentally rolls the session.
//
// Trade-off: an agent that crashes and restarts faster than
// sessionIdleGap (e.g. a liveness-probe restart in <2m) won't trigger
// rollover. Stale state from the prior session lingers until genuine
// idle gap is seen. Acceptable for now; proper fix is an agent-side
// session_id in the push protocol. Tracked in TODO.md.
const sessionIdleGap = 2 * time.Minute

// sessionLiveWindow is how fresh the last_push_at must be for the
// cluster to be considered "live" in the UI. After this much silence,
// read queries stop returning the cluster's data — the UI shows the
// cluster as gone dark instead of serving stale phantom state. Sized
// at ~15x the recommended heartbeat cadence so a handful of missed
// heartbeats doesn't flip the state visibly.
const sessionLiveWindow = 15 * time.Minute

// touchClusterSession records an incoming push for a cluster, rolling
// the session boundary forward when there's been a >sessionIdleGap
// quiet period. Called once per callcenter batch, scoped to the set
// of distinct cluster_ids in the batch.
//
// Atomic via a single UPSERT so concurrent batches can't race into
// split sessions on the same cluster_id.
func touchClusterSession(ctx context.Context, db *gorm.DB, clusterID string, now time.Time) error {
	return db.WithContext(ctx).Exec(`
		INSERT INTO cluster_sessions (cluster_id, session_started_at, last_push_at)
		VALUES (?, ?, ?)
		ON CONFLICT (cluster_id) DO UPDATE SET
		  session_started_at = CASE
		    WHEN EXCLUDED.last_push_at - cluster_sessions.last_push_at > make_interval(secs => ?)
		    THEN EXCLUDED.last_push_at
		    ELSE cluster_sessions.session_started_at
		  END,
		  last_push_at = EXCLUDED.last_push_at
	`, clusterID, now, now, sessionIdleGap.Seconds()).Error
}

// LiveRecordFilter returns the SQL fragment that a read query should
// append to its WHERE to see only rows from the agent's current session
// for a currently-live cluster. Intended to be dropped into the existing
// `data->>'msg' != 'DELETE'` chains.
//
// Single string literal so the many read-site queries can embed it
// without hand-building a CTE. The sub-SELECT is index-friendly
// (cluster_sessions primary key is cluster_id).
const LiveRecordFilter = ` AND EXISTS (
	SELECT 1 FROM cluster_sessions cs
	WHERE cs.cluster_id = data->>'cluster_id'
	  AND received_at >= cs.session_started_at
	  AND cs.last_push_at >= NOW() - INTERVAL '15 minutes'
) `

// LiveRecordFilterAlias is the same predicate keyed off a table alias
// (e.g. `c.data`, `s.data`). Used in correlated subqueries where the
// bare column name would be ambiguous.
func LiveRecordFilterAlias(alias string) string {
	return ` AND EXISTS (
		SELECT 1 FROM cluster_sessions cs
		WHERE cs.cluster_id = ` + alias + `.data->>'cluster_id'
		  AND ` + alias + `.received_at >= cs.session_started_at
		  AND cs.last_push_at >= NOW() - INTERVAL '15 minutes'
	) `
}
