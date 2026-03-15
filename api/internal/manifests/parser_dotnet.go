package manifests

import (
	"strings"

	"github.com/google/uuid"
)

func parseCsproj(manifestID, content string) []ManifestDependency {
	return parseDotnetPackageTag(manifestID, content, "PackageReference")
}

func parseDirectoryPackagesProps(manifestID, content string) []ManifestDependency {
	return parseDotnetPackageTag(manifestID, content, "PackageVersion")
}

func parseDotnetPackageTag(manifestID, content, tagName string) []ManifestDependency {
	var deps []ManifestDependency
	lines := strings.Split(content, "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "<!--") {
			continue
		}
		if !strings.Contains(line, tagName) {
			continue
		}

		name := extractXMLAttribute(line, "Include")
		if name == "" {
			name = extractXMLAttribute(line, "Update")
		}
		version := extractXMLAttribute(line, "Version")

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

func extractXMLAttribute(line, attr string) string {
	attrPrefix := attr + `="`
	idx := strings.Index(line, attrPrefix)
	if idx == -1 {
		return ""
	}

	start := idx + len(attrPrefix)
	end := strings.Index(line[start:], `"`)
	if end == -1 {
		return ""
	}
	return line[start : start+end]
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
