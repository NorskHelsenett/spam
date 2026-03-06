package manifests

import (
	"strings"

	"github.com/google/uuid"
)

func parseRequirementsTxt(manifestID, content string) []ManifestDependency {
	var deps []ManifestDependency
	lines := strings.Split(content, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
			continue
		}

		var name, version, constraint string
		for _, op := range []string{"==", ">=", "<=", ">", "<", "~=", "!="} {
			if idx := strings.Index(line, op); idx != -1 {
				name = strings.TrimSpace(line[:idx])
				constraint = strings.TrimSpace(line[idx:])
				version = strings.TrimSpace(strings.TrimPrefix(constraint, op))
				break
			}
		}
		if name == "" {
			name = strings.TrimSpace(line)
			version = "*"
		}

		if name != "" {
			deps = append(deps, ManifestDependency{
				ID:         uuid.NewString(),
				ManifestID: manifestID,
				Name:       name,
				Version:    version,
				Constraint: constraint,
				Ecosystem:  "pypi",
				Direct:     true,
			})
		}
	}
	return deps
}

func parsePipfile(manifestID, content string) []ManifestDependency {
	var deps []ManifestDependency
	lines := strings.Split(content, "\n")
	currentSection := ""

	for _, line := range lines {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "[packages]"):
			currentSection = "production"
			continue
		case strings.HasPrefix(line, "[dev-packages]"):
			currentSection = "development"
			continue
		case strings.HasPrefix(line, "["):
			currentSection = ""
			continue
		}
		if currentSection == "" || !strings.Contains(line, "=") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		name := strings.TrimSpace(parts[0])
		versionStr := strings.Trim(strings.TrimSpace(parts[1]), `"'`)
		version := versionStr
		if version != "*" {
			version = strings.TrimPrefix(versionStr, "==")
		}
		if name != "" {
			deps = append(deps, ManifestDependency{
				ID:         uuid.NewString(),
				ManifestID: manifestID,
				Name:       name,
				Version:    version,
				Constraint: versionStr,
				Ecosystem:  "pypi",
				Scope:      currentSection,
				Direct:     true,
			})
		}
	}

	return deps
}

func parsePoetryLock(manifestID, content string) []ManifestDependency {
	lines := strings.Split(content, "\n")
	var deps []ManifestDependency
	seen := map[string]struct{}{}

	var inPackage bool
	var name, version, scope string

	flush := func() {
		if name == "" || version == "" {
			return
		}
		if scope == "" {
			scope = "production"
		}
		k := name + "|" + version + "|" + scope
		if _, ok := seen[k]; ok {
			return
		}
		seen[k] = struct{}{}
		deps = append(deps, ManifestDependency{
			ID:         uuid.NewString(),
			ManifestID: manifestID,
			Name:       name,
			Version:    version,
			Constraint: version,
			Ecosystem:  "pypi",
			Scope:      scope,
			Direct:     false,
		})
	}

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "[[package]]" {
			if inPackage {
				flush()
			}
			inPackage = true
			name, version, scope = "", "", ""
			continue
		}
		if !inPackage || trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if strings.HasPrefix(trimmed, "name = ") {
			name = strings.Trim(strings.TrimPrefix(trimmed, "name = "), `"'`)
			continue
		}
		if strings.HasPrefix(trimmed, "version = ") {
			version = strings.Trim(strings.TrimPrefix(trimmed, "version = "), `"'`)
			continue
		}
		if strings.HasPrefix(trimmed, "category = ") {
			cat := strings.Trim(strings.TrimPrefix(trimmed, "category = "), `"'`)
			switch cat {
			case "main":
				scope = "production"
			case "dev":
				scope = "development"
			default:
				scope = cat
			}
		}
	}
	if inPackage {
		flush()
	}
	return deps
}

func parsePyprojectToml(manifestID, content string) []ManifestDependency {
	var deps []ManifestDependency
	lines := strings.Split(content, "\n")
	currentSection := ""

	for _, line := range lines {
		line = strings.TrimSpace(line)

		if strings.HasPrefix(line, "[tool.poetry.dependencies]") {
			currentSection = "production"
			continue
		}
		if strings.HasPrefix(line, "[tool.poetry.dev-dependencies]") ||
			strings.HasPrefix(line, "[tool.poetry.group.dev.dependencies]") {
			currentSection = "development"
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
				if name == "python" {
					continue
				}

				versionStr := strings.TrimSpace(parts[1])
				versionStr = strings.Trim(versionStr, `"'`)

				version := versionStr
				if strings.HasPrefix(versionStr, "^") || strings.HasPrefix(versionStr, "~") {
					version = strings.TrimPrefix(strings.TrimPrefix(versionStr, "^"), "~")
				}

				if name != "" {
					deps = append(deps, ManifestDependency{
						ID:         uuid.NewString(),
						ManifestID: manifestID,
						Name:       name,
						Version:    version,
						Constraint: versionStr,
						Ecosystem:  "pypi",
						Scope:      currentSection,
						Direct:     true,
					})
				}
			}
		}
	}

	return deps
}

func extractPythonVersion(content string) string {
	lines := strings.Split(content, "\n")
	inDependencies := false

	for _, line := range lines {
		line = strings.TrimSpace(line)

		if strings.HasPrefix(line, "[tool.poetry.dependencies]") {
			inDependencies = true
			continue
		}
		if strings.HasPrefix(line, "[") {
			inDependencies = false
			continue
		}

		if inDependencies && strings.HasPrefix(line, "python = ") {
			versionStr := strings.TrimPrefix(line, "python = ")
			versionStr = strings.Trim(versionStr, `"'`)
			for _, prefix := range []string{"^", "~", ">=", "<=", ">", "<"} {
				versionStr = strings.TrimPrefix(versionStr, prefix)
			}
			return strings.TrimSpace(versionStr)
		}
	}
	return ""
}
