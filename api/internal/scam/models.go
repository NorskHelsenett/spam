package scam

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/datatypes"
)

// Record is a live-state row for a single cluster resource.
// The table acts as a materialized view: upserts on ingest, deletes on DELETE events.
type Record struct {
	ID         uuid.UUID      `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"id"`
	Data       datatypes.JSON `gorm:"type:jsonb;not null" json:"data"`
	ReceivedAt time.Time      `gorm:"not null;index" json:"received_at"`
}

func (Record) TableName() string { return "cluster_record" }

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

// validKinds is the set of record kinds SCAM emits.
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
}

// validEvents is the set of event types SCAM emits.
var validEvents = map[string]bool{
	"INITIAL":  true,
	"ADD":      true,
	"UPDATE":   true,
	"DELETE":   true,
	"EXPOSURE": true,
}
