package manifests

import (
	"encoding/json"
	"strings"

	"github.com/google/uuid"
)

func parseCargoToml(manifestID, content string) []ManifestDependency {
	var deps []ManifestDependency
	lines := strings.Split(content, "\n")
	currentSection := ""

	for _, line := range lines {
		line = strings.TrimSpace(line)

		if strings.HasPrefix(line, "[dependencies]") {
			currentSection = "production"
			continue
		}
		if strings.HasPrefix(line, "[dev-dependencies]") {
			currentSection = "development"
			continue
		}
		if strings.HasPrefix(line, "[build-dependencies]") {
			currentSection = "build"
			continue
		}
		if strings.HasPrefix(line, "[") {
			currentSection = ""
			continue
		}

		if currentSection != "" && strings.Contains(line, "=") && !strings.HasPrefix(line, "#") {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				name := strings.TrimSpace(parts[0])
				versionStr := strings.TrimSpace(parts[1])
				versionStr = strings.Trim(versionStr, `"'`)

				version := versionStr
				if strings.HasPrefix(versionStr, "{") {
					if idx := strings.Index(versionStr, `version = "`); idx != -1 {
						start := idx + 11
						if end := strings.Index(versionStr[start:], `"`); end != -1 {
							version = versionStr[start : start+end]
						}
					} else {
						version = "*"
					}
				}

				if name != "" {
					deps = append(deps, ManifestDependency{
						ID:         uuid.NewString(),
						ManifestID: manifestID,
						Name:       name,
						Version:    version,
						Constraint: versionStr,
						Ecosystem:  "cargo",
						Scope:      currentSection,
						Direct:     true,
					})
				}
			}
		}
	}

	return deps
}

func parseGemfile(manifestID, content string) []ManifestDependency {
	var deps []ManifestDependency
	lines := strings.Split(content, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "gem ") || strings.HasPrefix(line, "#") {
			continue
		}

		line = strings.TrimPrefix(line, "gem ")
		var name, version string
		if idx := strings.Index(line, "'"); idx != -1 {
			start := idx + 1
			if end := strings.Index(line[start:], "'"); end != -1 {
				name = line[start : start+end]
				line = line[start+end+1:]
			}
		} else if idx := strings.Index(line, `"`); idx != -1 {
			start := idx + 1
			if end := strings.Index(line[start:], `"`); end != -1 {
				name = line[start : start+end]
				line = line[start+end+1:]
			}
		}

		if strings.Contains(line, "'") {
			if idx := strings.Index(line, "'"); idx != -1 {
				start := idx + 1
				if end := strings.Index(line[start:], "'"); end != -1 {
					version = line[start : start+end]
				}
			}
		} else if strings.Contains(line, `"`) {
			if idx := strings.Index(line, `"`); idx != -1 {
				start := idx + 1
				if end := strings.Index(line[start:], `"`); end != -1 {
					version = line[start : start+end]
				}
			}
		}

		if version == "" {
			version = "*"
		}
		if name != "" {
			deps = append(deps, ManifestDependency{
				ID:         uuid.NewString(),
				ManifestID: manifestID,
				Name:       name,
				Version:    version,
				Ecosystem:  "rubygems",
				Direct:     true,
			})
		}
	}

	return deps
}

func parseComposerJSON(manifestID, content string) []ManifestDependency {
	var pkg struct {
		Require    map[string]string `json:"require"`
		RequireDev map[string]string `json:"require-dev"`
	}

	if err := json.Unmarshal([]byte(content), &pkg); err != nil {
		return nil
	}

	var deps []ManifestDependency
	for name, version := range pkg.Require {
		if name == "php" {
			continue
		}
		deps = append(deps, ManifestDependency{
			ID:         uuid.NewString(),
			ManifestID: manifestID,
			Name:       name,
			Version:    strings.TrimLeft(version, "^~"),
			Constraint: version,
			Ecosystem:  "packagist",
			Scope:      "production",
			Direct:     true,
		})
	}
	for name, version := range pkg.RequireDev {
		if name == "php" {
			continue
		}
		deps = append(deps, ManifestDependency{
			ID:         uuid.NewString(),
			ManifestID: manifestID,
			Name:       name,
			Version:    strings.TrimLeft(version, "^~"),
			Constraint: version,
			Ecosystem:  "packagist",
			Scope:      "development",
			Direct:     true,
		})
	}

	return deps
}
