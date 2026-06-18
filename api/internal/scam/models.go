package scam

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/datatypes"
)

// Record is a live-state row for a single cluster resource.
// The table acts as a materialized view: upserts on ingest, tombstones
// (is_present=false) on DELETE events and snapshot reconciles.
//
// Lifecycle columns are first-class so reads don't have to JSONB-extract
// to filter for "currently present"; data->>'msg' is dual-written for
// backward compatibility with existing readers and is migrated out in a
// later sweep.
//
// EventID is the agent-side monotonic id stamped on each record. SCAM
// resets it per process start; SPAM uses it via cluster_sessions
// .last_seen_event_id to ACK the highest id stored per cluster, so
// SCAM can detect drift (mismatch -> reconcile snapshot).
// Index notes: cluster_record is extremely write-heavy (every SCAM agent
// rewrites its records continuously — far more UPDATEs than INSERTs), so
// each secondary index is pure write amplification unless something
// actually reads it. ReceivedAt and EventID previously carried `index`
// tags that GORM materialised into idx_cluster_record_received_at /
// idx_cluster_record_event_id; both showed zero scans in
// pg_stat_user_indexes (received_at filters are served as residuals behind
// the cluster_id/namespace indexes; event_id is only ever written here —
// the ACK counter lives on cluster_sessions). The tags are dropped so
// AutoMigrate won't recreate the indexes after the one-off DROP in
// 20260618_drop_unused_cluster_record_indexes.sql.
type Record struct {
	ID             uuid.UUID      `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"id"`
	Data           datatypes.JSON `gorm:"type:jsonb;not null" json:"data"`
	ReceivedAt     time.Time      `gorm:"not null" json:"received_at"`
	IsPresent      bool           `gorm:"not null;default:true" json:"is_present"`
	FirstSeenAt    time.Time      `gorm:"not null;default:now()" json:"first_seen_at"`
	LastChangeAt   time.Time      `gorm:"not null;default:now()" json:"last_change_at"`
	TombstonedAt   *time.Time     `json:"tombstoned_at,omitempty"`
	LastSnapshotID *string        `json:"last_snapshot_id,omitempty"`
	EventID        *int64         `gorm:"column:event_id" json:"event_id,omitempty"`
}

func (Record) TableName() string { return "cluster_record" }

// Cluster is a first-class cluster entity promoted from the
// `cluster_id` string that SCAM agents send in every Record. It exists
// so ACL grants can reference clusters directly and so admins can
// attach a friendly display name to an otherwise opaque id. Rows are
// created on first-heartbeat by the SCAM handler; no grants are seeded
// by default (clusters are deny-by-default).
//
// ClusterID is the kube-system Namespace UID — the Kubernetes-canonical
// per-install fingerprint that SCAM extracts client-side. The Ror*
// columns are an optional binding to ROR's identity domain: when an
// agent reports `ror_metadata`, the slug/name/env land here so the ACL
// filter can resolve ROR-sourced grants (which speak slug) back to the
// cluster_id used as the join key everywhere else.
type Cluster struct {
	ID             string    `gorm:"primaryKey;size:36" json:"id"`
	ClusterID      string    `gorm:"size:255;uniqueIndex;not null" json:"cluster_id"`
	DisplayName    string    `gorm:"size:255" json:"display_name,omitempty"`
	RorSlug        string    `gorm:"size:255;column:ror_slug" json:"ror_slug,omitempty"`
	RorClusterName string    `gorm:"size:255;column:ror_cluster_name" json:"ror_cluster_name,omitempty"`
	RorEnv         string    `gorm:"size:255;column:ror_env" json:"ror_env,omitempty"`
	// RorClusterUID is ROR's cluster UUID (the apikey identifier ROR keys
	// ACL grants by — post identifier-migration). Distinct from ror_slug,
	// which stays the human-readable slug; the ACL filter resolves
	// UUID-keyed grants against this column.
	RorClusterUID string `gorm:"size:255;column:ror_cluster_uid" json:"ror_cluster_uid,omitempty"`
	FirstSeenAt    time.Time `json:"first_seen_at"`
	CreatedAt      time.Time `json:"created_at"`
}

func (Cluster) TableName() string { return "clusters" }

// RorMetadata is the optional ROR-binding view that SCAM attaches to
// every record once a cluster has resolved its ROR identity. It is
// auxiliary — SPAM joins everything on the top-level `cluster_id`
// (kube-system Namespace UID) — but it lets the ACL filter map a
// ROR-sourced grant (which speaks slug) back onto the cluster_id used
// throughout the rest of the schema. Field names mirror SCAM's slog
// group: `ror_metadata.cluster_id` is the ROR slug, not a kube id.
type RorMetadata struct {
	ClusterID   string `json:"cluster_id,omitempty"`
	ClusterName string `json:"cluster_name,omitempty"`
	Env         string `json:"env,omitempty"`
	// ClusterUID is ROR's cluster UUID — the apikey identifier ROR keys
	// ACL grants by (post identifier-migration). SCAM emits it alongside
	// the slug (ClusterID) so SPAM can resolve a UUID-keyed grant without
	// losing the readable slug. Empty from pre-UID agents.
	ClusterUID string `json:"cluster_uid,omitempty"`
}

// Incoming is the expected shape of each record POSTed by a SCAM agent.
// Fields are validated on ingest; the full object is stored as JSONB in Data.
// Agents are anonymous (no registration or shared secret), so data integrity
// is enforced per-field before a row is persisted.
type Incoming struct {
	Time        string       `json:"time"`
	Level       string       `json:"level"`
	Msg         string       `json:"msg"`  // event: INITIAL, ADD, UPDATE, DELETE, EXPOSURE
	Kind        string       `json:"kind"` // Container, Service, Ingress, ...
	Cluster     string       `json:"cluster,omitempty"`
	ClusterID   string       `json:"cluster_id,omitempty"`
	Environment string       `json:"environment,omitempty"`
	RorMetadata *RorMetadata `json:"ror_metadata,omitempty"`
	// Resource identity fields — used to compute the upsert key.
	UID       string `json:"uid,omitempty"`
	PodUID    string `json:"pod_uid,omitempty"`
	Container string `json:"container,omitempty"`

	// Additional fields below are parsed for validation only. They are also
	// available to SQL queries via the raw JSONB column.
	Name         string        `json:"name,omitempty"`
	Namespace    string        `json:"namespace,omitempty"`
	Owner        string        `json:"owner,omitempty"`
	OwnerKind    string        `json:"owner_kind,omitempty"`
	PodPhase     string        `json:"pod_phase,omitempty"`
	ServiceType  string        `json:"service_type,omitempty"`
	IngressClass string        `json:"ingress_class,omitempty"`
	TLSSecret    string        `json:"tls_secret,omitempty"`
	Registry     string        `json:"registry,omitempty"`
	Image        string        `json:"image,omitempty"`
	Tag          string        `json:"tag,omitempty"`
	Digest       string        `json:"digest,omitempty"`
	Hostnames    []string      `json:"hostnames,omitempty"`
	Hosts        []string      `json:"hosts,omitempty"`
	LBIPs        []string      `json:"lb_ips,omitempty"`
	Rules        []IngressRule `json:"rules,omitempty"`

	// Snapshot-only fields. Present on kind="Snapshot" records:
	//   SNAPSHOT_BEGIN — snapshot_id + snapshot_type ("init"|"reconcile")
	//   SNAPSHOT      — snapshot_id + target_kind + resource_keys (the
	//                   authoritative set of currently-present rows for
	//                   target_kind in this cluster)
	//   SNAPSHOT_END  — snapshot_id (terminator)
	SnapshotID   string   `json:"snapshot_id,omitempty"`
	SnapshotType string   `json:"snapshot_type,omitempty"`
	TargetKind   string   `json:"target_kind,omitempty"`
	ResourceKeys []string `json:"resource_keys,omitempty"`

	// EventID is SCAM's per-process monotonic id. Absent on older
	// agents — those records contribute nothing to per-cluster
	// last_seen_event_id and the comparison is effectively skipped.
	EventID uint64 `json:"event_id,omitempty"`
}

// IngressRule is the shape of each element in an Ingress record's `rules` array.
// Only the host field is validated here; the rest of the rule (paths, backends)
// is passed through as JSONB for the UI to render.
type IngressRule struct {
	Host string `json:"host,omitempty"`
}

// ResourceKey returns the unique identifier for this resource within its cluster.
func (r Incoming) ResourceKey() string {
	if r.Kind == "Container" {
		return r.ClusterID + ":Container:" + r.PodUID + "/" + r.Container
	}
	return r.ClusterID + ":" + r.Kind + ":" + r.UID
}

// validKinds is the set of record kinds SCAM emits. Snapshot is a
// meta-record (not a resource itself) — it carries an authoritative
// key list per target_kind that the ingest handler uses to tombstone
// rows the cluster no longer reports.
var validKinds = map[string]bool{
	"Container":       true,
	"Service":         true,
	"Ingress":         true,
	"IngressClass":    true,
	"Gateway":         true,
	"GatewayClass":    true,
	"HTTPRoute":       true,
	"GRPCRoute":       true,
	"TLSRoute":        true,
	"TCPRoute":        true,
	"IngressRoute":    true,
	"IngressRouteTCP": true,
	"IngressRouteUDP": true,
	"EndpointSlice":   true,
	"Snapshot":        true,
}

// validEvents is the set of event types SCAM emits. SNAPSHOT and its
// BEGIN/END envelope are emitted with kind=Snapshot; SNAPSHOT carries
// the resource-key list, BEGIN/END are transaction markers.
var validEvents = map[string]bool{
	"INITIAL":         true,
	"ADD":             true,
	"UPDATE":          true,
	"DELETE":          true,
	"EXPOSURE":        true,
	"SNAPSHOT":        true,
	"SNAPSHOT_BEGIN":  true,
	"SNAPSHOT_END":    true,
}
