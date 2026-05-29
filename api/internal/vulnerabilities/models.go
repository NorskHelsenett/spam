package vulnerabilities

import (
	"time"

	"github.com/google/uuid"
)

// ComponentVulnerability caches an OSV vulnerability result for a versioned PURL.
// Rows are upserted on each lookup; checked_at is updated to track staleness.
type ComponentVulnerability struct {
	ID        uuid.UUID `gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	PURL        string    `gorm:"column:purl;not null;index:idx_component_vuln_purl"`
	VulnID      string    `gorm:"not null"` // CVE-YYYY-NNNNN or GHSA-xxxx
	Summary     string
	Description string    // full details / Markdown
	Severity    string    // CRITICAL, HIGH, MEDIUM, LOW, or empty
	FixedIn     string
	Source      string    `gorm:"not null;default:'osv'"`
	CheckedAt   time.Time `gorm:"not null"`
}

func (ComponentVulnerability) TableName() string { return "component_vulnerabilities" }

// ComponentVEX records a manual VEX override for a PURL+vuln pair.
// status values mirror the CycloneDX VEX spec:
//
//	affected, not_affected, fixed, under_investigation
//
// Append-only since the triage-ack work: a new row supersedes the prior
// one (which is revoked) rather than UPDATE-overwriting, so history is
// preserved. The (purl, vuln_id, COALESCE(asset_scope,'')) partial
// uniqueIndex (created in 20260528_create_triage_acknowledgments.sql)
// enforces "one live row per scope" — global plus per-image acks can
// coexist.
type ComponentVEX struct {
	ID            uuid.UUID  `gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	PURL          string     `gorm:"not null"`
	VulnID        string     `gorm:"not null"`
	Status        string     `gorm:"not null"` // affected | not_affected | fixed | under_investigation
	Justification string     // code_not_reachable, protected_by_mitigating_control, ...
	Detail        string
	CreatedAt     time.Time
	// Audit + acknowledgment fields (added 2026-05-28). Nullable so
	// rows created before the migration keep working until they're
	// next revoked.
	CreatedBy   string     `gorm:"column:created_by"`
	SnoozeUntil *time.Time `gorm:"column:snooze_until"`
	ReasonText  string     `gorm:"column:reason_text;not null;default:''"`
	// AssetScope narrows a VEX to a single asset. Format:
	//   "image:<digest>"  — suppresses this CVE only on the given image
	//   "cluster:<id>"    — suppresses on every image in the cluster
	//   ""                — global (current legacy behaviour: per-purl)
	AssetScope string     `gorm:"column:asset_scope"`
	RevokedAt  *time.Time `gorm:"column:revoked_at"`
	RevokedBy  string     `gorm:"column:revoked_by"`
}

func (ComponentVEX) TableName() string { return "component_vex" }
