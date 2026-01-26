package inventory

import (
	"os"
	"path/filepath"
	"testing"
)

func TestStripPURLVersion(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"pkg:golang/github.com/google/uuid@v1.6.0", "pkg:golang/github.com/google/uuid"},
		{"pkg:npm/%40fontsource/inter@5.2.8", "pkg:npm/%40fontsource/inter"},
		{"pkg:golang/github.com/jackc/pgservicefile@v0.0.0-20240606120523-5a60cdf6a761", "pkg:golang/github.com/jackc/pgservicefile"},
		{"pkg:npm/acorn@8.15.0?foo=bar#subpath", "pkg:npm/acorn"},
		{"pkg:golang/github.com/norskhelsenett/spam", "pkg:golang/github.com/norskhelsenett/spam"}, // no version
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := stripPURLVersion(tt.input)
			if got != tt.expected {
				t.Errorf("stripPURLVersion(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

func TestEcosystemFromPURL(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"pkg:golang/github.com/google/uuid@v1.6.0", "golang"},
		{"pkg:npm/%40fontsource/inter@5.2.8", "npm"},
		{"pkg:maven/org.apache/commons@1.0", "maven"},
		{"", ""},
		{"invalid", ""},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := ecosystemFromPURL(tt.input)
			if got != tt.expected {
				t.Errorf("ecosystemFromPURL(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

func TestParseCycloneDX_Deduplication(t *testing.T) {
	// Test that multiple versions of the same package deduplicate to one base PURL
	sbomJSON := `{
		"components": [
			{"name": "uuid", "version": "v1.6.0", "purl": "pkg:golang/github.com/google/uuid@v1.6.0"},
			{"name": "uuid", "version": "v1.5.0", "purl": "pkg:golang/github.com/google/uuid@v1.5.0"},
			{"name": "lodash", "version": "4.17.21", "purl": "pkg:npm/lodash@4.17.21"},
			{"name": "spam", "purl": "pkg:golang/github.com/norskhelsenett/spam"}
		]
	}`

	components, err := ParseSBOM("cyclonedx-json", []byte(sbomJSON))
	if err != nil {
		t.Fatalf("ParseSBOM error: %v", err)
	}

	if len(components) != 4 {
		t.Errorf("expected 4 components, got %d", len(components))
	}

	// Count unique base PURLs (what would become unique Component records)
	basePURLs := make(map[string][]string) // base PURL -> versions
	for _, c := range components {
		if c.PURL == "" {
			continue
		}
		base := stripPURLVersion(c.PURL)
		basePURLs[base] = append(basePURLs[base], c.Version)
	}

	// uuid@v1.6.0 and uuid@v1.5.0 should map to the same base PURL
	if len(basePURLs) != 3 {
		t.Errorf("expected 3 unique base PURLs, got %d", len(basePURLs))
		for base, versions := range basePURLs {
			t.Logf("  %s -> %v", base, versions)
		}
	}

	// Verify uuid has 2 versions
	uuidBase := "pkg:golang/github.com/google/uuid"
	if versions, ok := basePURLs[uuidBase]; !ok {
		t.Errorf("expected base PURL %s", uuidBase)
	} else if len(versions) != 2 {
		t.Errorf("expected 2 versions for uuid, got %d: %v", len(versions), versions)
	}
}

func TestParseCycloneDX_RealSBOM(t *testing.T) {
	// Find the sbom.cdx.json file (relative to repo root)
	sbomPath := filepath.Join("..", "..", "..", "sbom.cdx.json")

	data, err := os.ReadFile(sbomPath)
	if err != nil {
		t.Skipf("Skipping real SBOM test, file not found: %v", err)
	}

	parsed, err := ParseSBOMFull("cyclonedx-json", data)
	if err != nil {
		t.Fatalf("ParseSBOMFull error: %v", err)
	}

	t.Logf("Parsed %d total components from SBOM", len(parsed.Components))
	t.Logf("Parsed %d dependency entries from SBOM", len(parsed.Dependencies))

	// Count by ecosystem
	ecosystems := make(map[string]int)
	withPURL := 0
	withoutPURL := 0

	for _, c := range parsed.Components {
		if c.PURL != "" {
			withPURL++
			eco := ecosystemFromPURL(c.PURL)
			ecosystems[eco]++
		} else {
			withoutPURL++
		}
	}

	t.Logf("Components with PURL: %d", withPURL)
	t.Logf("Components without PURL: %d", withoutPURL)
	t.Logf("By ecosystem: %v", ecosystems)

	// Count unique base PURLs (simulates what DB would store)
	basePURLs := make(map[string]bool)
	for _, c := range parsed.Components {
		if c.PURL == "" {
			continue
		}
		base := stripPURLVersion(c.PURL)
		basePURLs[base] = true
	}

	t.Logf("Unique base PURLs (Component records): %d", len(basePURLs))

	// Count total dependencies
	totalDeps := 0
	for _, dep := range parsed.Dependencies {
		totalDeps += len(dep.DependsOn)
	}
	t.Logf("Total dependency links: %d", totalDeps)

	// Basic sanity checks based on the known SBOM content
	if len(parsed.Components) < 40 {
		t.Errorf("Expected at least 40 components, got %d", len(parsed.Components))
	}
	if ecosystems["golang"] < 15 {
		t.Errorf("Expected at least 15 golang components, got %d", ecosystems["golang"])
	}
	if ecosystems["npm"] < 15 {
		t.Errorf("Expected at least 15 npm components, got %d", ecosystems["npm"])
	}
	if len(parsed.Dependencies) < 10 {
		t.Errorf("Expected at least 10 dependency entries, got %d", len(parsed.Dependencies))
	}
}

func TestParseCycloneDX_ComponentsWithoutPURL(t *testing.T) {
	// Some components in CycloneDX don't have PURLs (e.g., application type)
	sbomJSON := `{
		"components": [
			{"name": "web/package-lock.json", "type": "application"},
			{"name": "api/go.mod", "type": "application"},
			{"name": "lodash", "version": "4.17.21", "purl": "pkg:npm/lodash@4.17.21"}
		]
	}`

	components, err := ParseSBOM("cyclonedx-json", []byte(sbomJSON))
	if err != nil {
		t.Fatalf("ParseSBOM error: %v", err)
	}

	if len(components) != 3 {
		t.Errorf("expected 3 components, got %d", len(components))
	}

	// Count components with and without PURL
	withPURL := 0
	withoutPURL := 0
	for _, c := range components {
		if c.PURL != "" {
			withPURL++
		} else {
			withoutPURL++
		}
	}

	if withPURL != 1 {
		t.Errorf("expected 1 component with PURL, got %d", withPURL)
	}
	if withoutPURL != 2 {
		t.Errorf("expected 2 components without PURL, got %d", withoutPURL)
	}
}

func TestParseSPDX(t *testing.T) {
	sbomJSON := `{
		"packages": [
			{
				"name": "lodash",
				"versionInfo": "4.17.21",
				"externalRefs": [
					{"referenceType": "purl", "referenceLocator": "pkg:npm/lodash@4.17.21"}
				]
			},
			{
				"name": "express",
				"versionInfo": "4.18.0"
			}
		]
	}`

	components, err := ParseSBOM("spdx-json", []byte(sbomJSON))
	if err != nil {
		t.Fatalf("ParseSBOM error: %v", err)
	}

	if len(components) != 2 {
		t.Errorf("expected 2 components, got %d", len(components))
	}

	// Find lodash and verify PURL extraction
	var lodash *ParsedComponent
	for i := range components {
		if components[i].Name == "lodash" {
			lodash = &components[i]
			break
		}
	}

	if lodash == nil {
		t.Fatal("lodash component not found")
	}
	if lodash.PURL != "pkg:npm/lodash@4.17.21" {
		t.Errorf("expected PURL pkg:npm/lodash@4.17.21, got %s", lodash.PURL)
	}
	if lodash.Version != "4.17.21" {
		t.Errorf("expected version 4.17.21, got %s", lodash.Version)
	}
}
