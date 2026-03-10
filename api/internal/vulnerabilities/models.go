package vulnerabilities

import (
	"time"

	"github.com/google/uuid"
)

// ComponentVulnerability caches an OSV vulnerability result for a versioned PURL.
// Rows are upserted on each lookup; checked_at is updated to track staleness.
type ComponentVulnerability struct {
	ID        uuid.UUID `gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	PURL      string    `gorm:"not null;index:idx_component_vuln_purl"`
	VulnID    string    `gorm:"not null"` // CVE-YYYY-NNNNN or GHSA-xxxx
	Summary   string
	Severity  string    // CRITICAL, HIGH, MEDIUM, LOW, or empty
	FixedIn   string
	Source    string    `gorm:"not null;default:'osv'"`
	CheckedAt time.Time `gorm:"not null"`
}

func (ComponentVulnerability) TableName() string { return "component_vulnerabilities" }

// ComponentVEX records a manual VEX override for a PURL+vuln pair.
// status values mirror the CycloneDX VEX spec:
//
//	affected, not_affected, fixed, under_investigation
type ComponentVEX struct {
	ID            uuid.UUID `gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	PURL          string    `gorm:"not null;uniqueIndex:idx_component_vex_purl_vuln"`
	VulnID        string    `gorm:"not null;uniqueIndex:idx_component_vex_purl_vuln"`
	Status        string    `gorm:"not null"` // affected | not_affected | fixed | under_investigation
	Justification string    // code_not_reachable, protected_by_mitigating_control, ...
	Detail        string
	CreatedAt     time.Time
}

func (ComponentVEX) TableName() string { return "component_vex" }
