package main

import "testing"

func TestCountSBOMComponents_ImplicitSingleRootCycloneDX(t *testing.T) {
	payload := []byte(`{
		"bomFormat":"CycloneDX",
		"specVersion":"1.6",
		"components":[{"bom-ref":"pkg:npm/app@1.0.0","purl":"pkg:npm/app@1.0.0"}],
		"dependencies":[{"ref":"pkg:npm/app@1.0.0","dependsOn":[]}]
	}`)

	if got := countSBOMComponents(payload); got != 0 {
		t.Fatalf("expected 0 components, got %d", got)
	}
}

func TestCountSBOMComponents_SingleSPDXRootPackage(t *testing.T) {
	payload := []byte(`{"spdxVersion":"SPDX-2.3","packages":[{"SPDXID":"SPDXRef-Root"}]}`)

	if got := countSBOMComponents(payload); got != 0 {
		t.Fatalf("expected 0 components, got %d", got)
	}
}
