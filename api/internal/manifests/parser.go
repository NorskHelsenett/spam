package manifests

import (
	"encoding/json"
	"path/filepath"
	"strings"

	"github.com/google/uuid"
	"gorm.io/datatypes"
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

		// Extract runtime version and store in metadata
		metadata := extractMetadata(manifestType, file.Content)
		if len(metadata) > 0 {
			if metadataJSON, err := json.Marshal(metadata); err == nil {
				manifest.Metadata = datatypes.JSON(metadataJSON)
			}
		}

		// Parse dependencies based on type
		deps := parseDependenciesByType(manifest.ID, manifestType, file.Content)
		dependencies = append(dependencies, deps...)

		manifests = append(manifests, manifest)
	}

	return manifests, dependencies, nil
}

// extractMetadata extracts metadata like runtime version from manifest files
func extractMetadata(manifestType, content string) map[string]interface{} {
	metadata := make(map[string]interface{})

	switch manifestType {
	case "csproj":
		if version := extractDotNetVersion(content); version != "" {
			metadata["runtime_version"] = version
		}
	case "go.mod":
		if version := extractGoVersion(content); version != "" {
			metadata["runtime_version"] = version
		}
	case "pyproject.toml":
		if version := extractPythonVersion(content); version != "" {
			metadata["runtime_version"] = version
		}
	}

	return metadata
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
	case "packages.config":
		return parsePackagesConfig(manifestID, content)
	case "package.json":
		return parsePackageJSON(manifestID, content)
	case "go.mod":
		return parseGoMod(manifestID, content)
	case "requirements.txt":
		return parseRequirementsTxt(manifestID, content)
	case "Pipfile":
		return parsePipfile(manifestID, content)
	case "pyproject.toml":
		return parsePyprojectToml(manifestID, content)
	case "pom.xml":
		return parsePomXml(manifestID, content)
	case "Cargo.toml":
		return parseCargoToml(manifestID, content)
	case "Gemfile":
		return parseGemfile(manifestID, content)
	case "composer.json":
		return parseComposerJSON(manifestID, content)
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
		// Skip commented lines
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "<!--") {
			continue
		}

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
			Version:    strings.TrimLeft(version, "^~"),
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
			Version:    strings.TrimLeft(version, "^~"),
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

// parsePackagesConfig parses .NET packages.config files
func parsePackagesConfig(manifestID, content string) []ManifestDependency {
	var deps []ManifestDependency
	lines := strings.Split(content, "\n")

	for _, line := range lines {
		// Skip commented lines
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

// parseRequirementsTxt parses Python requirements.txt files
func parseRequirementsTxt(manifestID, content string) []ManifestDependency {
	var deps []ManifestDependency
	lines := strings.Split(content, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		// Skip comments and empty lines
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Skip -r, -e, and other options
		if strings.HasPrefix(line, "-") {
			continue
		}

		// Parse package name and version
		var name, version, constraint string

		// Handle different version operators
		for _, op := range []string{"==", ">=", "<=", ">", "<", "~=", "!="} {
			if idx := strings.Index(line, op); idx != -1 {
				name = strings.TrimSpace(line[:idx])
				constraint = strings.TrimSpace(line[idx:])
				version = strings.TrimPrefix(constraint, op)
				version = strings.TrimSpace(version)
				break
			}
		}

		// If no version specified
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

// parsePipfile parses Python Pipfile
func parsePipfile(manifestID, content string) []ManifestDependency {
	var deps []ManifestDependency
	lines := strings.Split(content, "\n")
	currentSection := ""

	for _, line := range lines {
		line = strings.TrimSpace(line)

		if strings.HasPrefix(line, "[packages]") {
			currentSection = "production"
			continue
		}
		if strings.HasPrefix(line, "[dev-packages]") {
			currentSection = "development"
			continue
		}
		if strings.HasPrefix(line, "[") {
			currentSection = ""
			continue
		}

		if currentSection != "" && strings.Contains(line, "=") {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				name := strings.TrimSpace(parts[0])
				versionStr := strings.TrimSpace(parts[1])
				versionStr = strings.Trim(versionStr, `"'`)

				version := versionStr
				if version == "*" {
					version = "*"
				} else {
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
		}
	}

	return deps
}

// parsePyprojectToml parses Python pyproject.toml files (Poetry format)
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
				// Skip python version requirement
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

// parsePomXml parses Java Maven pom.xml files
func parsePomXml(manifestID, content string) []ManifestDependency {
	var deps []ManifestDependency
	lines := strings.Split(content, "\n")

	var currentDep struct {
		groupID    string
		artifactID string
		version    string
		scope      string
	}
	inDependency := false

	for _, line := range lines {
		line = strings.TrimSpace(line)

		if strings.HasPrefix(line, "<dependency>") {
			inDependency = true
			currentDep = struct {
				groupID    string
				artifactID string
				version    string
				scope      string
			}{}
			continue
		}
		if strings.HasPrefix(line, "</dependency>") {
			if currentDep.groupID != "" && currentDep.artifactID != "" {
				name := currentDep.groupID + ":" + currentDep.artifactID
				version := currentDep.version
				if version == "" {
					version = "*"
				}
				scope := currentDep.scope
				if scope == "" {
					scope = "compile"
				}

				deps = append(deps, ManifestDependency{
					ID:         uuid.NewString(),
					ManifestID: manifestID,
					Name:       name,
					Version:    version,
					Ecosystem:  "maven",
					Scope:      scope,
					Direct:     true,
				})
			}
			inDependency = false
			continue
		}

		if inDependency {
			if strings.Contains(line, "<groupId>") {
				currentDep.groupID = extractXMLValue(line, "groupId")
			} else if strings.Contains(line, "<artifactId>") {
				currentDep.artifactID = extractXMLValue(line, "artifactId")
			} else if strings.Contains(line, "<version>") {
				currentDep.version = extractXMLValue(line, "version")
			} else if strings.Contains(line, "<scope>") {
				currentDep.scope = extractXMLValue(line, "scope")
			}
		}
	}

	return deps
}

// parseCargoToml parses Rust Cargo.toml files
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

				// Handle version or full object
				version := versionStr
				if strings.HasPrefix(versionStr, "{") {
					// Complex dependency, try to extract version
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

// parseGemfile parses Ruby Gemfile
func parseGemfile(manifestID, content string) []ManifestDependency {
	var deps []ManifestDependency
	lines := strings.Split(content, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)

		if !strings.HasPrefix(line, "gem ") || strings.HasPrefix(line, "#") {
			continue
		}

		// Remove 'gem ' prefix
		line = strings.TrimPrefix(line, "gem ")

		// Extract gem name (first quoted string)
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

		// Try to extract version
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

// parseComposerJSON parses PHP composer.json files
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
		// Skip PHP version requirement
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

// extractXMLValue extracts the value from a simple XML tag
func extractXMLValue(line, tag string) string {
	start := strings.Index(line, ">")
	end := strings.Index(line, "</"+tag+">")
	if start != -1 && end != -1 && end > start {
		return strings.TrimSpace(line[start+1 : end])
	}
	return ""
}

// extractDotNetVersion extracts the target framework version from csproj
func extractDotNetVersion(content string) string {
	lines := strings.Split(content, "\n")
	for _, line := range lines {
		if strings.Contains(line, "<TargetFramework>") {
			return extractXMLValue(line, "TargetFramework")
		}
	}
	return ""
}

// extractGoVersion extracts the Go version from go.mod
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

// extractPythonVersion extracts the Python version from pyproject.toml
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
			// Remove constraint operators like ^, ~, >=
			for _, prefix := range []string{"^", "~", ">=", "<=", ">", "<"} {
				versionStr = strings.TrimPrefix(versionStr, prefix)
			}
			return strings.TrimSpace(versionStr)
		}
	}
	return ""
}
