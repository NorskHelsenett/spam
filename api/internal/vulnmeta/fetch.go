package vulnmeta

import (
	"context"
	"errors"
	"fmt"
	"log"
	"regexp"
	"strings"

	"gorm.io/gorm"
)

// cvePattern matches canonical CVE identifiers — the subset of vuln IDs
// where EUVD supplement is worth attempting. GHSA-* / BIT-* / PYSEC-*
// IDs are resolved in OSV only.
var cvePattern = regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`)

// ErrUpstreamTransient is returned when Enrich found no metadata AND at
// least one upstream fetch failed with a transient error (403, 429, 5xx,
// decode mismatch, network timeout). Callers should distinguish this
// from a true "(nil, nil)" not-found, since caching the miss would
// suppress later successful fetches of the same vuln_id.
var ErrUpstreamTransient = errors.New("vulnmeta: upstream transient error")

// Enrich fetches metadata for vuln_id from external sources and
// upserts into vuln_metadata. OSV is always tried first; for CVE-
// prefixed IDs we also pull EUVD and layer its fields on top of the
// OSV record. Errors from either source are logged and swallowed —
// returning an error here would stall the enrichment queue for one
// flaky vuln.
//
// Returns (nil, nil) when neither source had the ID (uncommon — OSV
// is comprehensive). The caller can tell "not enriched" from "cache
// miss" by whether the result is nil or populated.
func Enrich(ctx context.Context, db *gorm.DB, vulnID string) (*Metadata, error) {
	vulnID = strings.TrimSpace(vulnID)
	if vulnID == "" || vulnID == "_none" {
		return nil, nil
	}

	var transient bool
	osvVuln, osvRaw, err := fetchOSV(ctx, vulnID)
	if err != nil {
		log.Printf("vulnmeta: osv fetch %s: %v", vulnID, err)
		transient = true
	}

	var m *Metadata
	if osvVuln != nil {
		m = osvVuln.toMetadata(osvRaw)
	}

	// EUVD supplement for CVE IDs — even when OSV succeeded, EUVD
	// often has CVSS v4 scoring where OSV stops at v3.
	if cvePattern.MatchString(strings.ToUpper(vulnID)) {
		euvd, euvdRaw, err := fetchEUVD(ctx, vulnID)
		if err != nil {
			log.Printf("vulnmeta: euvd fetch %s: %v", vulnID, err)
			transient = true
		}
		if euvd != nil {
			if m == nil {
				m = euvdToMetadata(vulnID, euvd, euvdRaw)
			} else {
				euvd.mergeInto(m, euvdRaw)
			}
		}
	}

	if m == nil {
		if transient {
			return nil, ErrUpstreamTransient
		}
		return nil, nil
	}

	// Compute canonical_id from the final (possibly merged) alias set
	// so count queries and dashboards collapse CVE / GHSA / BIT
	// variants of the same advisory to one row.
	m.CanonicalID = PickCanonical(m.VulnID, Aliases(m))

	if err := Upsert(ctx, db, m); err != nil {
		return nil, fmt.Errorf("upsert: %w", err)
	}
	return m, nil
}

// euvdToMetadata builds a fresh Metadata when EUVD is the only source
// with a hit (rare, but happens for EU-disclosed CVEs that haven't
// been ingested by OSV yet).
func euvdToMetadata(vulnID string, e *euvdEntry, raw []byte) *Metadata {
	m := &Metadata{
		VulnID:      vulnID,
		Title:       "",
		Description: strings.TrimSpace(e.Description),
		CVSSVector:  e.BaseScoreVec,
		CVSSScore:   e.BaseScore,
	}
	if !e.DatePublished.IsZero() {
		t := e.DatePublished.UTC()
		m.PublishedAt = &t
	}
	if !e.DateUpdated.IsZero() {
		t := e.DateUpdated.UTC()
		m.ModifiedAt = &t
	}
	m.Aliases = marshalJSON(mergeStringSet([]string{vulnID}, []string(e.Aliases)))
	m.References = marshalJSON(refsFromEUVDURLs([]string(e.References)))
	m.Sources = marshalJSON([]string{"euvd"})
	m.CWEs = marshalJSON([]string{})
	m.Severity = cvssVectorToLabel(e.BaseScoreVec)
	m.RawJSON = marshalJSON(map[string][]byte{"euvd": raw})
	return m
}
