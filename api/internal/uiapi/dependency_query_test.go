package uiapi

import (
	"strings"
	"testing"
)

func TestParseDependencySearchQuery_PlainTextFallsBack(t *testing.T) {
	parsed, err := parseDependencySearchQuery("debug")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if parsed.Structured {
		t.Fatalf("expected unstructured fallback for plain text")
	}
}

func TestParseDependencySearchQuery_ExactAndRangeAndOr(t *testing.T) {
	parsed, err := parseDependencySearchQuery("debug@4.4.2 || lodash <=4.17")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !parsed.Structured {
		t.Fatalf("expected structured query")
	}
	if len(parsed.Clauses) != 2 {
		t.Fatalf("expected 2 clauses, got %d", len(parsed.Clauses))
	}

	if parsed.Clauses[0].Name != "debug" || parsed.Clauses[0].Comparator != "=" || parsed.Clauses[0].RawVersion != "4.4.2" {
		t.Fatalf("unexpected first clause: %#v", parsed.Clauses[0])
	}
	if parsed.Clauses[1].Name != "lodash" || parsed.Clauses[1].Comparator != "<=" || parsed.Clauses[1].RawVersion != "4.17" {
		t.Fatalf("unexpected second clause: %#v", parsed.Clauses[1])
	}
}

func TestParseDependencySearchQuery_ScopedPackage(t *testing.T) {
	parsed, err := parseDependencySearchQuery("@scope/pkg@1.2.3")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !parsed.Structured {
		t.Fatalf("expected structured query")
	}
	if len(parsed.Clauses) != 1 {
		t.Fatalf("expected 1 clause, got %d", len(parsed.Clauses))
	}
	if parsed.Clauses[0].Name != "@scope/pkg" {
		t.Fatalf("unexpected clause name: %q", parsed.Clauses[0].Name)
	}
}

func TestParseDependencySearchQuery_InvalidRangeVersion(t *testing.T) {
	_, err := parseDependencySearchQuery("debug <= latest")
	if err == nil {
		t.Fatalf("expected error")
	}
}

func TestSemverComparatorTarget(t *testing.T) {
	tests := []struct {
		name      string
		op        string
		sv        semverSpec
		wantOp    string
		wantMajor int
		wantMinor int
		wantPatch int
	}{
		{name: "lte major expands to next major", op: "<=", sv: semverSpec{Major: 4, Parts: 1}, wantOp: "<", wantMajor: 5, wantMinor: 0, wantPatch: 0},
		{name: "lte minor expands to next minor", op: "<=", sv: semverSpec{Major: 4, Minor: 4, Parts: 2}, wantOp: "<", wantMajor: 4, wantMinor: 5, wantPatch: 0},
		{name: "lt minor anchors patch zero", op: "<", sv: semverSpec{Major: 4, Minor: 4, Parts: 2}, wantOp: "<", wantMajor: 4, wantMinor: 4, wantPatch: 0},
		{name: "exact stays exact", op: "=", sv: semverSpec{Major: 4, Minor: 4, Patch: 2, Parts: 3}, wantOp: "=", wantMajor: 4, wantMinor: 4, wantPatch: 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			op, major, minor, patch := semverComparatorTarget(tt.op, tt.sv)
			if op != tt.wantOp || major != tt.wantMajor || minor != tt.wantMinor || patch != tt.wantPatch {
				t.Fatalf("got (%s,%d,%d,%d), want (%s,%d,%d,%d)", op, major, minor, patch, tt.wantOp, tt.wantMajor, tt.wantMinor, tt.wantPatch)
			}
		})
	}
}

func TestBuildStructuredDependencyPredicate(t *testing.T) {
	parsed, err := parseDependencySearchQuery("debug<=4 || lodash")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !parsed.Structured {
		t.Fatalf("expected structured query")
	}

	predicate, args := buildStructuredDependencyPredicate("scv.name", "COALESCE(scv.version, '')", parsed.Clauses)
	if predicate == "" {
		t.Fatalf("expected predicate")
	}
	if !strings.Contains(predicate, " OR ") {
		t.Fatalf("expected OR predicate, got %q", predicate)
	}
	if len(args) == 0 {
		t.Fatalf("expected query args")
	}
}

func TestBuildStructuredDependencyPredicate_NoRegexQuestionMark(t *testing.T) {
	parsed, err := parseDependencySearchQuery("jinzhu/now@v1.1.0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !parsed.Structured {
		t.Fatalf("expected structured query")
	}

	predicate, _ := buildStructuredDependencyPredicate("scv.name", "COALESCE(scv.version, NULLIF(scv.purl_version, ''), '')", parsed.Clauses)
	if strings.Contains(predicate, "v?") {
		t.Fatalf("predicate should not contain literal '?' in regex: %q", predicate)
	}
}

func TestBuildStructuredDependencyPredicate_NameUsesILikeFallback(t *testing.T) {
	parsed, err := parseDependencySearchQuery("jinzhu/now<v1.1.0 || jinzhu/now")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !parsed.Structured {
		t.Fatalf("expected structured query")
	}

	predicate, args := buildStructuredDependencyPredicate("scv.name", "COALESCE(scv.version, '')", parsed.Clauses)
	if !strings.Contains(predicate, "ILIKE ?") {
		t.Fatalf("expected ILIKE fallback in predicate, got %q", predicate)
	}
	foundWildcard := false
	for _, arg := range args {
		if s, ok := arg.(string); ok && s == "%jinzhu/now%" {
			foundWildcard = true
			break
		}
	}
	if !foundWildcard {
		t.Fatalf("expected wildcard arg for name fallback, args=%v", args)
	}
}
