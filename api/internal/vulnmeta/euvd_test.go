package vulnmeta

import (
	"encoding/json"
	"strings"
	"testing"
)

// EUVD's real API emits localised timestamps and newline-joined strings
// for aliases/references rather than the RFC3339 + []string we first
// assumed. This sample is minimised from a real response for
// CVE-2026-4878 so a future schema change shows up as a test failure
// instead of silently breaking enrichment.
const euvdSampleResponse = `{
  "items": [{
    "id": "EUVD-2026-20910",
    "description": "libcap TOCTOU in cap_set_file().",
    "datePublished": "Apr 9, 2026, 2:49:02 PM",
    "dateUpdated": "Apr 18, 2026, 5:34:10 PM",
    "baseScore": 6.7,
    "baseScoreVersion": "3.1",
    "baseScoreVector": "CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:U/C:H/I:H/A:H",
    "aliases": "CVE-2026-4878\n",
    "references": "https://example.com/a\nhttps://example.com/b\n"
  }],
  "total": 1
}`

func TestEUVDDecodeRealShape(t *testing.T) {
	var r euvdSearchResult
	if err := json.Unmarshal([]byte(euvdSampleResponse), &r); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(r.Items) != 1 {
		t.Fatalf("items: got %d want 1", len(r.Items))
	}
	it := r.Items[0]

	if it.ID != "EUVD-2026-20910" {
		t.Errorf("id: %q", it.ID)
	}
	if it.BaseScoreVers != "3.1" {
		t.Errorf("baseScoreVersion not read: %q", it.BaseScoreVers)
	}
	if it.DatePublished.IsZero() {
		t.Error("datePublished not parsed")
	}
	if it.DateUpdated.IsZero() {
		t.Error("dateUpdated not parsed")
	}
	if len(it.Aliases) != 1 || it.Aliases[0] != "CVE-2026-4878" {
		t.Errorf("aliases: %v", it.Aliases)
	}
	if len(it.References) != 2 {
		t.Errorf("references: %v", it.References)
	}
}

func TestEUVDStringListArrayForm(t *testing.T) {
	var l euvdStringList
	if err := json.Unmarshal([]byte(`["a","b",""]`), &l); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(l) != 2 || l[0] != "a" || l[1] != "b" {
		t.Errorf("array form: %v", l)
	}
}

func TestEUVDStringListStringForm(t *testing.T) {
	var l euvdStringList
	if err := json.Unmarshal([]byte(`"one\ntwo\n\nthree"`), &l); err != nil {
		t.Fatalf("decode: %v", err)
	}
	got := strings.Join(l, ",")
	if got != "one,two,three" {
		t.Errorf("string form: %q", got)
	}
}

func TestEUVDTimeRFC3339Fallback(t *testing.T) {
	var ts euvdTime
	if err := json.Unmarshal([]byte(`"2026-04-09T14:49:02Z"`), &ts); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if ts.IsZero() {
		t.Error("rfc3339 not parsed")
	}
}

func TestEUVDSearchMatchUsesAliases(t *testing.T) {
	// Simulates the search-result matching in fetchEUVD: the top-level
	// item's id is EUVD-*, but we want to find the entry whose
	// aliases contain the queried CVE. Before the fix, aliases
	// decoded as an empty []string and this match never hit.
	var r euvdSearchResult
	if err := json.Unmarshal([]byte(euvdSampleResponse), &r); err != nil {
		t.Fatalf("decode: %v", err)
	}
	needle := "CVE-2026-4878"
	var matched bool
	for _, item := range r.Items {
		for _, a := range item.Aliases {
			if a == needle {
				matched = true
			}
		}
	}
	if !matched {
		t.Fatal("alias match did not hit — aliases list was not decoded")
	}
}
