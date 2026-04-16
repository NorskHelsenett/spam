package scam

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/datatypes"
)

// Record is a generic ingest row — just the raw JSONB payload and a timestamp.
type Record struct {
	ID         uuid.UUID      `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"id"`
	Data       datatypes.JSON `gorm:"type:jsonb;not null" json:"data"`
	ReceivedAt time.Time      `gorm:"not null;index" json:"received_at"`
}

func (Record) TableName() string { return "cluster_record" }

// Incoming is the expected shape of each record POSTed by a SCAM agent.
// Fields are validated on ingest; the full object is stored as JSONB in Data.
type Incoming struct {
	Time        string `json:"time"`
	Level       string `json:"level"`
	Msg         string `json:"msg"`  // event: INITIAL, ADD, UPDATE, DELETE
	Kind        string `json:"kind"` // Container, Service, Ingress, ...
	Cluster     string `json:"cluster,omitempty"`
	ClusterID   string `json:"cluster_id,omitempty"`
	Environment string `json:"environment,omitempty"`
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
}

// validEvents is the set of event types SCAM emits.
var validEvents = map[string]bool{
	"INITIAL":  true,
	"ADD":      true,
	"UPDATE":   true,
	"DELETE":   true,
	"EXPOSURE": true,
}
