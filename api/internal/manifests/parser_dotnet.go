package manifests

import (
	"strings"

	"github.com/google/uuid"
)

func parseCsproj(manifestID, content string) []ManifestDependency {
	var deps []ManifestDependency
	lines := strings.Split(content, "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "<!--") {
			continue
		}
		if !strings.Contains(line, "PackageReference") {
			continue
		}

		var name, version string
		if idx := strings.Index(line, `Include="`); idx != -1 {
			start := idx + 9
			if end := strings.Index(line[start:], `"`); end != -1 {
				name = line[start : start+end]
			}
		}
		if idx := strings.Index(line, `Version="`); idx != -1 {
			start := idx + 9
			if end := strings.Index(line[start:], `"`); end != -1 {
				version = line[start : start+end]
			}
		}

		if name != "" && version != "" {
			deps = append(deps, ManifestDependency{
				ID:         uuid.NewString(),
				ManifestID: manifestID,
				Name:       name,
				Version:    version,
				Ecosystem:  "nuget",
				Direct:     true,
			})
		}
	}
	return deps
}

func parsePackagesConfig(manifestID, content string) []ManifestDependency {
	var deps []ManifestDependency
	lines := strings.Split(content, "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "<!--") {
			continue
		}
		if !strings.Contains(line, "<package ") {
			continue
		}

		var name, version string
		if idx := strings.Index(line, `id="`); idx != -1 {
			start := idx + 4
			if end := strings.Index(line[start:], `"`); end != -1 {
				name = line[start : start+end]
			}
		}
		if idx := strings.Index(line, `version="`); idx != -1 {
			start := idx + 9
			if end := strings.Index(line[start:], `"`); end != -1 {
				version = line[start : start+end]
			}
		}

		if name != "" && version != "" {
			deps = append(deps, ManifestDependency{
				ID:         uuid.NewString(),
				ManifestID: manifestID,
				Name:       name,
				Version:    version,
				Ecosystem:  "nuget",
				Direct:     true,
			})
		}
	}
	return deps
}

func extractDotNetVersion(content string) string {
	lines := strings.Split(content, "\n")
	for _, line := range lines {
		if strings.Contains(line, "<TargetFramework>") {
			return extractXMLValue(line, "TargetFramework")
		}
	}
	return ""
}
