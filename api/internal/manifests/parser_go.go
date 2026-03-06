package manifests

import (
	"strings"

	"github.com/google/uuid"
)

func parseGoMod(manifestID, content string) []ManifestDependency {
	var deps []ManifestDependency
	lines := strings.Split(content, "\n")
	inRequire := false

	for _, line := range lines {
		line = strings.TrimSpace(line)

		if strings.HasPrefix(line, "require (") {
			inRequire = true
			continue
		}
		if inRequire && line == ")" {
			inRequire = false
			continue
		}

		if strings.HasPrefix(line, "require ") || inRequire {
			parts := strings.Fields(strings.TrimPrefix(line, "require "))
			if len(parts) >= 2 {
				name := parts[0]
				version := parts[1]
				if name != "" && version != "" {
					deps = append(deps, ManifestDependency{
						ID:         uuid.NewString(),
						ManifestID: manifestID,
						Name:       name,
						Version:    version,
						Ecosystem:  "golang",
						Direct:     !strings.Contains(line, "// indirect"),
					})
				}
			}
		}
	}

	return deps
}

func extractGoVersion(content string) string {
	lines := strings.Split(content, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "go ") {
			return strings.TrimPrefix(line, "go ")
		}
	}
	return ""
}
