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
type Record struct {
	ID             uuid.UUID      `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"id"`
	Data           datatypes.JSON `gorm:"type:jsonb;not null" json:"data"`
	ReceivedAt     time.Time      `gorm:"not null;index" json:"received_at"`
	IsPresent      bool           `gorm:"not null;default:true" json:"is_present"`
	FirstSeenAt    time.Time      `gorm:"not null;default:now()" json:"first_seen_at"`
	LastChangeAt   time.Time      `gorm:"not null;default:now()" json:"last_change_at"`
	TombstonedAt   *time.Time     `json:"tombstoned_at,omitempty"`
	LastSnapshotID *string        `json:"last_snapshot_id,omitempty"`
}

func (Record) TableName() string { return "cluster_record" }

// Cluster is a first-class cluster entity promoted from the
// `cluster_id` string that SCAM agents send in every Record. It exists
// so ACL grants can reference clusters directly and so admins can
// attach a friendly display name to an otherwise opaque id. Rows are
// created on first-heartbeat by the SCAM handler; no grants are seeded
// by default (clusters are deny-by-default).
type Cluster struct {
	ID          string    `gorm:"primaryKey;size:36" json:"id"`
	ClusterID   string    `gorm:"size:255;uniqueIndex;not null" json:"cluster_id"`
	DisplayName string    `gorm:"size:255" json:"display_name,omitempty"`
	FirstSeenAt time.Time `json:"first_seen_at"`
	CreatedAt   time.Time `json:"created_at"`
}

func (Cluster) TableName() string { return "clusters" }

// Incoming is the expected shape of each record POSTed by a SCAM agent.
// Fields are validated on ingest; the full object is stored as JSONB in Data.
// Agents are anonymous (no registration or shared secret), so data integrity
// is enforced per-field before a row is persisted.
type Incoming struct {
	Time        string `json:"time"`
	Level       string `json:"level"`
	Msg         string `json:"msg"`  // event: INITIAL, ADD, UPDATE, DELETE, EXPOSURE
	Kind        string `json:"kind"` // Container, Service, Ingress, ...
	Cluster     string `json:"cluster,omitempty"`
	ClusterID   string `json:"cluster_id,omitempty"`
	Environment string `json:"environment,omitempty"`
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
