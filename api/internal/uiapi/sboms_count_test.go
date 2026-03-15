package uiapi

import "testing"

func TestCountComponentsFromContent_ImplicitSingleRootCycloneDX(t *testing.T) {
	payload := []byte(`{
		"bomFormat":"CycloneDX",
		"specVersion":"1.6",
		"components":[{"bom-ref":"pkg:npm/app@1.0.0","purl":"pkg:npm/app@1.0.0"}],
		"dependencies":[{"ref":"pkg:npm/app@1.0.0","dependsOn":[]}]
	}`)

	if got := countComponentsFromContent("cyclonedx-json", payload); got != 0 {
		t.Fatalf("expected 0 components, got %d", got)
	}
}

func TestCountComponentsFromContent_SingleSPDXRootPackage(t *testing.T) {
	payload := []byte(`{"spdxVersion":"SPDX-2.3","packages":[{"SPDXID":"SPDXRef-Root"}]}`)

	if got := countComponentsFromContent("spdx-json", payload); got != 0 {
		t.Fatalf("expected 0 components, got %d", got)
	}
}
