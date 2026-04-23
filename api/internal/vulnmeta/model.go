// Package vulnmeta caches enriched vulnerability advisory data
// (CVSS, CWE, references, aliases, published/modified dates, descriptions)
// fetched from external feeds. OSV is the primary source; EUVD layers
// CVE-specific fields for CVE-YYYY-NNNN IDs when available.
//
// The package is split so call sites can import just what they need:
//   - model.go  — Metadata / Reference / CWE types, GORM mapping
//   - store.go  — Get / Upsert against the vuln_metadata table
//   - osv.go    — OSV.dev API client
//   - euvd.go   — ENISA EUVD API client (optional supplement)
//   - fetch.go  — Enrich: orchestrates OSV + EUVD, merges, upserts
package vulnmeta

import (
	"time"

	"gorm.io/datatypes"
)

// Reference is one external link cited by an advisory.
// Types follow the OSV schema (ADVISORY, WEB, REPORT, FIX, PACKAGE,
// EVIDENCE) but we pass through unknown types so new references don't
// get silently dropped.
type Reference struct {
	URL   string `json:"url"`
	Type  string `json:"type,omitempty"`
	Label string `json:"label,omitempty"`
}

// Metadata is the enriched payload stored per vuln_id. Nil timestamps
// mean "not reported by any source yet" — don't mistake for "epoch".
type Metadata struct {
	VulnID      string         `json:"vuln_id"       gorm:"column:vuln_id;primaryKey"`
	Title       string         `json:"title"         gorm:"column:title"`
	Description string         `json:"description"   gorm:"column:description"`
	Severity    string         `json:"severity"      gorm:"column:severity"`
	CVSSScore   float32        `json:"cvss_score"    gorm:"column:cvss_score"`
	CVSSVector  string         `json:"cvss_vector"   gorm:"column:cvss_vector"`
	CWEs        datatypes.JSON `json:"cwes"          gorm:"column:cwes"`
	References  datatypes.JSON `json:"references"    gorm:"column:references"`
	Aliases     datatypes.JSON `json:"aliases"       gorm:"column:aliases"`
	Sources     datatypes.JSON `json:"sources"       gorm:"column:sources"`
	PublishedAt *time.Time     `json:"published_at"  gorm:"column:published_at"`
	ModifiedAt  *time.Time     `json:"modified_at"   gorm:"column:modified_at"`
	RawJSON     datatypes.JSON `json:"raw_json"      gorm:"column:raw_json"`
	FetchedAt   time.Time      `json:"fetched_at"    gorm:"column:fetched_at"`
}

// TableName maps to the migration-created table. GORM would otherwise
// pluralize to "vuln_metadatas".
func (Metadata) TableName() string {
	return "vuln_metadata"
}
