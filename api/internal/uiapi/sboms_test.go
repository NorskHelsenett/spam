package uiapi

import (
	"os"
	"testing"
)

func TestDetectSBOMFormat_CycloneDX(t *testing.T) {
	content, err := os.ReadFile("testdata/cyclonedx.json")
	if err != nil {
		t.Fatalf("read testdata: %v", err)
	}

	got := detectSBOMFormat(content)
	if got != "cyclonedx-json" {
		t.Fatalf("expected cyclonedx-json, got %q", got)
	}
}

func TestExtractCycloneDXComponents(t *testing.T) {
	content, err := os.ReadFile("testdata/cyclonedx.json")
	if err != nil {
		t.Fatalf("read testdata: %v", err)
	}

	components, err := extractCycloneDXComponents(content)
	if err != nil {
		t.Fatalf("extractCycloneDXComponents: %v", err)
	}

	const wantCount = 116
	if len(components) != wantCount {
		t.Fatalf("expected %d components, got %d", wantCount, len(components))
	}

	// Every component must have a bom-ref or purl so the materialized view
	// can assign a unique component_ref (matching the SQL view logic).
	for i, c := range components {
		if c.BomRef == "" && c.Purl == "" {
			t.Errorf("component[%d] (%q) has neither bom-ref nor purl", i, c.Name)
		}
	}

	// Spot-check a known component from the file.
	found := false
	for _, c := range components {
		if c.Purl == "pkg:npm/%40ampproject/remapping@2.3.0" {
			found = true
			if c.Name != "@ampproject/remapping" {
				t.Errorf("unexpected name %q for @ampproject/remapping", c.Name)
			}
			if c.Version != "2.3.0" {
				t.Errorf("unexpected version %q for @ampproject/remapping", c.Version)
			}
			break
		}
	}
	if !found {
		t.Error("expected to find pkg:npm/%40ampproject/remapping@2.3.0 in components")
	}
}
