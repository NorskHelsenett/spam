package acl

import (
	"testing"

	"github.com/NorskHelsenett/spam/internal/ror"
)

func TestPatternsFromLookup_GlobalReadDominates(t *testing.T) {
	lookup := &ror.LookupResponse{
		Scopes: map[string]ror.LookupScope{
			"ror": {Subject: map[string]ror.LookupAccess{
				ror.GlobalScopeSubject: {Read: true},
			}},
			// cluster grants are present but should be irrelevant once
			// global read is set — the wildcard must short-circuit.
			"cluster": {Subject: map[string]ror.LookupAccess{
				"c-alpha": {Read: true},
				"c-beta":  {Read: true},
			}},
		},
	}
	got := patternsFromLookup(lookup)
	if len(got) != 1 || !got[0].IsWildcard() {
		t.Fatalf("expected single wildcard pattern, got %#v", got)
	}
}

func TestPatternsFromLookup_PerClusterReadFiltersOutNonReaders(t *testing.T) {
	lookup := &ror.LookupResponse{
		Scopes: map[string]ror.LookupScope{
			"cluster": {Subject: map[string]ror.LookupAccess{
				"c-readable":  {Read: true},
				"c-writeonly": {Read: false, Create: true},
			}},
		},
	}
	got := patternsFromLookup(lookup)
	if len(got) != 1 {
		t.Fatalf("expected 1 pattern (only the readable cluster), got %d: %#v", len(got), got)
	}
	if got[0].ClusterID != "c-readable" {
		t.Fatalf("expected ClusterID c-readable, got %q", got[0].ClusterID)
	}
}

func TestPatternsFromLookup_NoClusterScopeReturnsNil(t *testing.T) {
	if got := patternsFromLookup(nil); got != nil {
		t.Fatalf("nil lookup should return nil, got %#v", got)
	}
	if got := patternsFromLookup(&ror.LookupResponse{}); got != nil {
		t.Fatalf("empty Scopes should return nil, got %#v", got)
	}
	if got := patternsFromLookup(&ror.LookupResponse{Scopes: map[string]ror.LookupScope{
		"project": {Subject: map[string]ror.LookupAccess{"p1": {Read: true}}},
	}}); got != nil {
		t.Fatalf("only non-cluster scopes should return nil, got %#v", got)
	}
}

func TestPatternsFromLookup_GlobalSubjectWithoutReadIsIgnored(t *testing.T) {
	// Write-only global (create=true, read=false) must not produce a
	// wildcard read grant. Useful guard so future tightening of write
	// flows doesn't accidentally widen reads.
	lookup := &ror.LookupResponse{
		Scopes: map[string]ror.LookupScope{
			"ror": {Subject: map[string]ror.LookupAccess{
				ror.GlobalScopeSubject: {Create: true},
			}},
			"cluster": {Subject: map[string]ror.LookupAccess{
				"c-x": {Read: true},
			}},
		},
	}
	got := patternsFromLookup(lookup)
	if len(got) != 1 || got[0].ClusterID != "c-x" {
		t.Fatalf("expected single per-cluster pattern for c-x, got %#v", got)
	}
}
