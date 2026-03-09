package manifests

import (
	"encoding/json"
	"path/filepath"
	"strings"

	"github.com/google/uuid"
	"gorm.io/datatypes"
)

// ManifestFile represents a raw manifest file from the runner
//
// NOTE: this includes both known dependency manifests and unknown files we
// intentionally persist for searchability.
type ManifestFile struct {
	Path    string `json:"path"`
	Content string `json:"content"`
}

// ParseManifests extracts dependencies from manifest files.
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
			manifestType = "unknown"
		}

		manifest := Manifest{
			ID:      uuid.NewString(),
			RunID:   runID,
			RepoID:  repoID,
			Path:    file.Path,
			Type:    manifestType,
			Content: file.Content,
		}

		metadata := extractMetadata(manifestType, file.Content)
		if len(metadata) > 0 {
			if metadataJSON, err := json.Marshal(metadata); err == nil {
				manifest.Metadata = datatypes.JSON(metadataJSON)
			}
		}

		deps := parseDependenciesByType(manifest.ID, manifestType, file.Content)
		dependencies = append(dependencies, deps...)
		manifests = append(manifests, manifest)
	}

	return manifests, dependencies, nil
}

// extractMetadata extracts metadata like runtime version from manifest files.
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
	pathSlash := filepath.ToSlash(path)
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
	case base == "bun.lock":
		return "bun.lock"
	case base == "bun.lockb":
		return "bun.lockb"
	case base == "pom.xml":
		return "pom.xml"
	case base == "build.gradle", base == "build.gradle.kts":
		return "gradle"
	case base == "gradle.lock":
		return "gradle.lock"
	case base == "gradle.properties":
		return "gradle.properties"
	case base == "settings.gradle", base == "settings.gradle.kts":
		return "settings.gradle"
	case base == "libs.versions.toml":
		return "libs.versions.toml"
	case base == "build.sbt":
		return "build.sbt"
	case strings.HasSuffix(pathSlash, "project/build.properties"):
		return "project/build.properties"
	case strings.HasSuffix(pathSlash, "project/plugins.sbt"):
		return "project/plugins.sbt"
	case base == "requirements.txt":
		return "requirements.txt"
	case base == "Pipfile":
		return "Pipfile"
	case base == "poetry.lock", base == "Pipfile.lock":
		return "poetry.lock"
	case base == "pyproject.toml":
		return "pyproject.toml"
	case base == "go.sum":
		return "go.sum"
	case base == "go.mod":
		return "go.mod"
	case base == "Cargo.toml":
		return "Cargo.toml"
	case base == "Cargo.lock":
		return "Cargo.lock"
	case base == "Gemfile":
		return "Gemfile"
	case base == "Gemfile.lock":
		return "Gemfile.lock"
	case base == "composer.json":
		return "composer.json"
	case base == "composer.lock":
		return "composer.lock"
	case base == "pubspec.yaml":
		return "pubspec.yaml"
	case base == "pubspec.lock":
		return "pubspec.lock"
	case base == "mix.exs":
		return "mix.exs"
	case base == "mix.lock":
		return "mix.lock"
	case base == "Package.swift":
		return "Package.swift"
	case base == "Podfile":
		return "Podfile"
	case base == "Podfile.lock":
		return "Podfile.lock"
	case base == "Cartfile":
		return "Cartfile"
	case base == "Cartfile.resolved":
		return "Cartfile.resolved"
	case base == "project.pbxproj":
		return "project.pbxproj"
	case base == "CMakeLists.txt":
		return "CMakeLists.txt"
	case base == "conanfile.txt":
		return "conanfile.txt"
	case base == "conanfile.py":
		return "conanfile.py"
	case base == "vcpkg.json":
		return "vcpkg.json"
	case base == "BUILD":
		return "BUILD"
	case base == "WORKSPACE":
		return "WORKSPACE"
	case base == "MODULE.bazel":
		return "MODULE.bazel"
	case base == "stack.yaml":
		return "stack.yaml"
	case strings.HasSuffix(base, ".cabal"):
		return "cabal"
	case base == "cabal.project":
		return "cabal.project"
	case base == "DESCRIPTION":
		return "DESCRIPTION"
	case base == "renv.lock":
		return "renv.lock"
	case base == "packrat.lock":
		return "packrat.lock"
	case base == "install.R":
		return "install.R"
	case base == "dune":
		return "dune"
	case base == "dune-project":
		return "dune-project"
	case base == "opam":
		return "opam"
	case base == "opam.locked":
		return "opam.locked"
	case base == "Project.toml":
		return "Project.toml"
	case base == "Manifest.toml":
		return "Manifest.toml"
	case base == "rebar.config":
		return "rebar.config"
	case base == "rebar.lock":
		return "rebar.lock"
	case strings.HasSuffix(base, ".rockspec"):
		return "rockspec"
	case base == "luarocks.lock":
		return "luarocks.lock"
	case base == "cpanfile":
		return "cpanfile"
	case base == "META.json":
		return "META.json"
	case base == "META.yml":
		return "META.yml"
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
	case "package-lock.json":
		return parsePackageLockJSON(manifestID, content)
	case "yarn.lock":
		return parseYarnLock(manifestID, content)
	case "pnpm-lock.yaml":
		return parsePnpmLockYAML(manifestID, content)
	case "bun.lock":
		return parseBunLock(manifestID, content)
	case "go.mod":
		return parseGoMod(manifestID, content)
	case "gradle":
		return parseGradle(manifestID, content)
	case "gradle.lock":
		return parseGradleLock(manifestID, content)
	case "settings.gradle":
		return parseGradleSettings(manifestID, content)
	case "libs.versions.toml":
		return parseGradleVersionCatalog(manifestID, content)
	case "build.sbt":
		return parseBuildSbt(manifestID, content)
	case "project/plugins.sbt":
		return parseSbtPlugins(manifestID, content)
	case "requirements.txt":
		return parseRequirementsTxt(manifestID, content)
	case "Pipfile":
		return parsePipfile(manifestID, content)
	case "poetry.lock":
		return parsePoetryLock(manifestID, content)
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
