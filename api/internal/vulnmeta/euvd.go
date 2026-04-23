package vulnmeta

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// euvdAPIBase is ENISA's public EUVD search API. The path +
// query format is published at https://euvd.enisa.europa.eu/ —
// it's the same endpoint the web UI hits. We use the search
// variant so a bare CVE id resolves whether EUVD has it under
// its own prefix (EUVD-YYYY-NNNN) or as a cross-referenced CVE.
const euvdAPIBase = "https://euvdservices.enisa.europa.eu/api/search"

var euvdClient = &http.Client{Timeout: 20 * time.Second}

// euvdEnabled lets operators turn the supplement off if EUVD is
// rate-limiting or the endpoint shape changes. Default-on —
// failure to reach EUVD is already non-fatal (we log and fall
// back to OSV-only), so a flag is mostly for opt-out in
// air-gapped environments.
func euvdEnabled() bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv("SPAM_EUVD_ENABLED")))
	return v != "false" && v != "0" && v != "no" && v != "off"
}

// euvdEntry is the subset of EUVD's response we use. EUVD's schema
// still evolves, so new fields are carried through via RawJSON in
// Metadata and only the well-defined ones are surfaced here.
type euvdEntry struct {
	ID            string    `json:"id"`             // EUVD-YYYY-NNNN
	Description   string    `json:"description"`
	DatePublished time.Time `json:"datePublished"`
	DateUpdated   time.Time `json:"dateUpdated"`
	BaseScore     float32   `json:"baseScore"`      // CVSS base
	BaseScoreVers string    `json:"baseScoreVers"`  // e.g. "3.1", "4.0"
	BaseScoreVec  string    `json:"baseScoreVector"`
	Aliases       []string  `json:"aliases"`        // cross-ref IDs (CVE-…)
	References    []string  `json:"references"`     // plain URLs
}

// euvdSearchResult mirrors /api/search's top-level shape.
type euvdSearchResult struct {
	Items []euvdEntry `json:"items"`
	Total int         `json:"total"`
}

// fetchEUVD looks up a CVE (or EUVD) ID in the EUVD database.
// Returns (nil, nil) if not found — callers treat that as "no
// supplement available" and proceed with OSV-only data.
//
// EUVD currently has the richest coverage for CVE-YYYY-NNNN IDs
// (especially CVSS v4.0 scoring post-2024); GHSA-* / BIT-* IDs
// generally return nothing, so callers usually only bother with
// CVE-prefixed IDs.
func fetchEUVD(ctx context.Context, vulnID string) (*euvdEntry, []byte, error) {
	if !euvdEnabled() {
		return nil, nil, nil
	}
	url := fmt.Sprintf("%s?text=%s", euvdAPIBase, vulnID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "spam-vuln-enricher/1.0")

	resp, err := euvdClient.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil, nil
	}
	if resp.StatusCode >= 400 {
		return nil, nil, fmt.Errorf("euvd: status %d", resp.StatusCode)
	}

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return nil, nil, err
	}

	var result euvdSearchResult
	if err := json.Unmarshal(raw, &result); err != nil {
		return nil, nil, fmt.Errorf("euvd: decode: %w", err)
	}
	if len(result.Items) == 0 {
		return nil, nil, nil
	}

	// Pick the entry whose id or aliases include the queried vuln_id
	// — "?text=" is a full-text search and can return near-matches.
	needle := strings.ToUpper(vulnID)
	for i := range result.Items {
		if strings.EqualFold(result.Items[i].ID, needle) {
			return &result.Items[i], raw, nil
		}
		for _, a := range result.Items[i].Aliases {
			if strings.EqualFold(a, needle) {
				return &result.Items[i], raw, nil
			}
		}
	}
	// No exact match → don't supplement with fuzzy hit.
	return nil, nil, nil
}

// mergeInto layers EUVD fields onto a Metadata built primarily
// from OSV. Only fills what OSV left blank or wrote weaker data
// for: CVSS (EUVD often has v4 where OSV only has v3), published/
// modified timestamps (EUVD may have corrected dates), and adds
// aliases + references as a set-union.
func (e *euvdEntry) mergeInto(m *Metadata, raw []byte) {
	if m == nil {
		return
	}

	// CVSS: prefer the higher-version vector regardless of source.
	if e.BaseScoreVec != "" && preferEUVDCVSS(m.CVSSVector, e.BaseScoreVers) {
		m.CVSSVector = e.BaseScoreVec
	}
	if e.BaseScore > 0 && m.CVSSScore == 0 {
		m.CVSSScore = e.BaseScore
	}

	// Dates: only fill if OSV didn't (OSV is usually more accurate
	// when it has them; EUVD fills gaps for EU-disclosed vulns that
	// predate OSV ingestion).
	if m.PublishedAt == nil && !e.DatePublished.IsZero() {
		t := e.DatePublished.UTC()
		m.PublishedAt = &t
	}
	if m.ModifiedAt == nil && !e.DateUpdated.IsZero() {
		t := e.DateUpdated.UTC()
		m.ModifiedAt = &t
	}

	// Description: fill only if empty — OSV's description is
	// usually better (proper markdown, structured).
	if m.Description == "" && e.Description != "" {
		m.Description = strings.TrimSpace(e.Description)
	}

	// Aliases + references: set-union, preserve existing order.
	m.Aliases = marshalJSON(mergeStringSet(decodeStringArray(m.Aliases), e.Aliases))
	m.References = marshalJSON(mergeReferenceSet(
		decodeReferenceArray(m.References),
		refsFromEUVDURLs(e.References),
	))

	// Sources: add "euvd" without dropping prior sources.
	m.Sources = marshalJSON(mergeStringSet(decodeStringArray(m.Sources), []string{"euvd"}))

	// Raw JSON: stash alongside OSV so future migrations can
	// re-derive fields from either source.
	var rawBlob map[string]json.RawMessage
	if len(m.RawJSON) > 0 {
		_ = json.Unmarshal(m.RawJSON, &rawBlob)
	}
	if rawBlob == nil {
		rawBlob = map[string]json.RawMessage{}
	}
	rawBlob["euvd"] = raw
	m.RawJSON = marshalJSON(rawBlob)

	m.FetchedAt = time.Now().UTC()
}

// preferEUVDCVSS returns true if EUVD's vector is a higher CVSS
// revision than what OSV published. We want the newer scoring
// scheme (4.0 > 3.1 > 3.0 > 2.0) even though it may produce a
// different severity bucket.
func preferEUVDCVSS(osvVector, euvdVers string) bool {
	if osvVector == "" {
		return true
	}
	if strings.HasPrefix(euvdVers, "4") && !strings.Contains(osvVector, "CVSS:4") {
		return true
	}
	if strings.HasPrefix(euvdVers, "3") && strings.Contains(osvVector, "CVSS:2") {
		return true
	}
	return false
}

func refsFromEUVDURLs(urls []string) []Reference {
	out := make([]Reference, 0, len(urls))
	for _, u := range urls {
		out = append(out, Reference{URL: u, Type: "WEB"})
	}
	return out
}

func mergeStringSet(a, b []string) []string {
	seen := make(map[string]struct{}, len(a)+len(b))
	out := make([]string, 0, len(a)+len(b))
	for _, s := range append(a, b...) {
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

func mergeReferenceSet(a, b []Reference) []Reference {
	seen := make(map[string]struct{}, len(a)+len(b))
	out := make([]Reference, 0, len(a)+len(b))
	for _, r := range append(a, b...) {
		if r.URL == "" {
			continue
		}
		if _, ok := seen[r.URL]; ok {
			continue
		}
		seen[r.URL] = struct{}{}
		out = append(out, r)
	}
	return out
}

func decodeStringArray(raw []byte) []string {
	if len(raw) == 0 {
		return nil
	}
	var out []string
	_ = json.Unmarshal(raw, &out)
	return out
}

func decodeReferenceArray(raw []byte) []Reference {
	if len(raw) == 0 {
		return nil
	}
	var out []Reference
	_ = json.Unmarshal(raw, &out)
	return out
}
