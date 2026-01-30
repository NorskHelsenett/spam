package manifests

import (
	"encoding/json"
	"path/filepath"
	"strings"

	"github.com/google/uuid"
)

// ManifestFile represents a raw manifest file from the runner
type ManifestFile struct {
	Path    string `json:"path"`
	Content string `json:"content"`
}

// ParseManifests extracts dependencies from manifest files
func ParseManifests(runID, repoID string, manifestsJSON []byte) ([]Manifest, []ManifestDependency, error) {
	var files []ManifestFile
	if err := json.Unmarshal(manifestsJSON, &files); err != nil {
		return nil, nil, err
	}

	var manifests []Manifest
	var dependencies []ManifestDependency

	for _, file := range files {
		manifestType := detectManifestType(file.Path)
		if manifestType == "" {
			continue
		}

		manifest := Manifest{
			ID:      uuid.NewString(),
			RunID:   runID,
			RepoID:  repoID,
			Path:    file.Path,
			Type:    manifestType,
			Content: file.Content,
		}

		// Parse dependencies based on type
		deps := parseDependenciesByType(manifest.ID, manifestType, file.Content)
		dependencies = append(dependencies, deps...)

		manifests = append(manifests, manifest)
	}

	return manifests, dependencies, nil
}

func detectManifestType(path string) string {
	base := filepath.Base(path)
	switch {
	case strings.HasSuffix(base, ".csproj"), strings.HasSuffix(base, ".fsproj"), strings.HasSuffix(base, ".vbproj"):
		return "csproj"
	case base == "packages.config":
		return "packages.config"
	case base == "package.json":
		return "package.json"
	case base == "package-lock.json":
		return "package-lock.json"
	case base == "yarn.lock":
		return "yarn.lock"
	case base == "pnpm-lock.yaml":
		return "pnpm-lock.yaml"
	case base == "pom.xml":
		return "pom.xml"
	case base == "build.gradle", base == "build.gradle.kts":
		return "gradle"
	case base == "requirements.txt":
		return "requirements.txt"
	case base == "Pipfile":
		return "Pipfile"
	case base == "poetry.lock", base == "Pipfile.lock":
		return "poetry.lock"
	case base == "pyproject.toml":
		return "pyproject.toml"
	case base == "go.mod":
		return "go.mod"
	case base == "Cargo.toml":
		return "Cargo.toml"
	case base == "Gemfile":
		return "Gemfile"
	case base == "composer.json":
		return "composer.json"
	default:
		return ""
	}
}

func parseDependenciesByType(manifestID, manifestType, content string) []ManifestDependency {
	switch manifestType {
	case "csproj":
		return parseCsproj(manifestID, content)
	case "package.json":
		return parsePackageJSON(manifestID, content)
	case "go.mod":
		return parseGoMod(manifestID, content)
	// Add more parsers as needed
	default:
		return nil
	}
}

func parseCsproj(manifestID, content string) []ManifestDependency {
	// Simple XML parsing for PackageReference
	var deps []ManifestDependency

	// This is a simple parser - you'd want a proper XML parser in production
	lines := strings.Split(content, "\n")
	for _, line := range lines {
		if !strings.Contains(line, "PackageReference") {
			continue
		}

		// Extract Include and Version attributes
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

func parsePackageJSON(manifestID, content string) []ManifestDependency {
	var pkg struct {
		Dependencies    map[string]string `json:"dependencies"`
		DevDependencies map[string]string `json:"devDependencies"`
	}

	if err := json.Unmarshal([]byte(content), &pkg); err != nil {
		return nil
	}

	var deps []ManifestDependency

	for name, version := range pkg.Dependencies {
		deps = append(deps, ManifestDependency{
			ID:         uuid.NewString(),
			ManifestID: manifestID,
			Name:       name,
			Version:    strings.TrimPrefix(version, "^"),
			Constraint: version,
			Ecosystem:  "npm",
			Scope:      "production",
			Direct:     true,
		})
	}

	for name, version := range pkg.DevDependencies {
		deps = append(deps, ManifestDependency{
			ID:         uuid.NewString(),
			ManifestID: manifestID,
			Name:       name,
			Version:    strings.TrimPrefix(version, "^"),
			Constraint: version,
			Ecosystem:  "npm",
			Scope:      "development",
			Direct:     true,
		})
	}

	return deps
}

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
