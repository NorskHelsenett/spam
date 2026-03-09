package manifests

import (
	"regexp"
	"strings"

	"github.com/google/uuid"
)

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

var gradleSimpleDepRE = regexp.MustCompile(`\b(?:api|implementation|compileOnly|runtimeOnly|testImplementation|testCompileOnly|testRuntimeOnly)\s*\(?\s*['"]([^:'"]+):([^:'"]+):([^'"]+)['"]\s*\)?`)
var gradleMapDepRE = regexp.MustCompile(`\b(?:api|implementation|compileOnly|runtimeOnly|testImplementation|testCompileOnly|testRuntimeOnly)\s+group:\s*['"]([^'"]+)['"]\s*,\s*name:\s*['"]([^'"]+)['"]\s*,\s*version:\s*['"]([^'"]+)['"]`)
var gradleSettingsPluginRE = regexp.MustCompile(`\bid\s*\(?\s*["']([^"']+)["']\s*\)?\s*version\s*["']([^"']+)["']`)
var sbtLibraryDepRE = regexp.MustCompile(`["']([^"']+)["']\s*%{1,3}\s*["']([^"']+)["']\s*%\s*["']([^"']+)["']`)
var sbtPluginRE = regexp.MustCompile(`addSbtPlugin\(\s*["']([^"']+)["']\s*%\s*["']([^"']+)["']\s*%\s*["']([^"']+)["']\s*\)`)

func parseGradle(manifestID, content string) []ManifestDependency {
	lines := strings.Split(content, "\n")
	var deps []ManifestDependency
	seen := map[string]struct{}{}

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "//") {
			continue
		}
		for _, m := range gradleSimpleDepRE.FindAllStringSubmatch(trimmed, -1) {
			name := m[1] + ":" + m[2]
			version := strings.TrimSpace(m[3])
			scope := "production"
			if strings.HasPrefix(trimmed, "test") {
				scope = "test"
			}
			k := name + "|" + version + "|" + scope
			if _, ok := seen[k]; ok {
				continue
			}
			seen[k] = struct{}{}
			deps = append(deps, ManifestDependency{ID: uuid.NewString(), ManifestID: manifestID, Name: name, Version: version, Constraint: version, Ecosystem: "maven", Scope: scope, Direct: true})
		}
		for _, m := range gradleMapDepRE.FindAllStringSubmatch(trimmed, -1) {
			name := m[1] + ":" + m[2]
			version := strings.TrimSpace(m[3])
			scope := "production"
			if strings.HasPrefix(trimmed, "test") {
				scope = "test"
			}
			k := name + "|" + version + "|" + scope
			if _, ok := seen[k]; ok {
				continue
			}
			seen[k] = struct{}{}
			deps = append(deps, ManifestDependency{ID: uuid.NewString(), ManifestID: manifestID, Name: name, Version: version, Constraint: version, Ecosystem: "maven", Scope: scope, Direct: true})
		}
	}
	return deps
}

func parseGradleLock(manifestID, content string) []ManifestDependency {
	lines := strings.Split(content, "\n")
	var deps []ManifestDependency
	seen := map[string]struct{}{}

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "//") {
			continue
		}
		entry := trimmed
		if idx := strings.Index(entry, "="); idx != -1 {
			entry = strings.TrimSpace(entry[:idx])
		}
		parts := strings.SplitN(entry, ":", 3)
		if len(parts) != 3 {
			continue
		}
		group, artifact, version := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]), strings.TrimSpace(parts[2])
		if group == "" || artifact == "" || version == "" {
			continue
		}
		name := group + ":" + artifact
		k := name + "|" + version
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}
		deps = append(deps, ManifestDependency{ID: uuid.NewString(), ManifestID: manifestID, Name: name, Version: version, Constraint: version, Ecosystem: "maven", Scope: "lockfile", Direct: false})
	}
	return deps
}

func parseGradleSettings(manifestID, content string) []ManifestDependency {
	lines := strings.Split(content, "\n")
	var deps []ManifestDependency
	seen := map[string]struct{}{}

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "//") {
			continue
		}
		for _, m := range gradleSettingsPluginRE.FindAllStringSubmatch(trimmed, -1) {
			name := strings.TrimSpace(m[1])
			version := strings.TrimSpace(m[2])
			if name == "" || version == "" {
				continue
			}
			k := name + "|" + version
			if _, ok := seen[k]; ok {
				continue
			}
			seen[k] = struct{}{}
			deps = append(deps, ManifestDependency{ID: uuid.NewString(), ManifestID: manifestID, Name: name, Version: version, Constraint: version, Ecosystem: "gradle-plugin", Scope: "plugin", Direct: true})
		}
	}
	return deps
}

func parseBuildSbt(manifestID, content string) []ManifestDependency {
	lines := strings.Split(content, "\n")
	var deps []ManifestDependency
	seen := map[string]struct{}{}

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "//") {
			continue
		}
		for _, m := range sbtLibraryDepRE.FindAllStringSubmatch(trimmed, -1) {
			name := strings.TrimSpace(m[1]) + ":" + strings.TrimSpace(m[2])
			version := strings.TrimSpace(m[3])
			if strings.HasPrefix(trimmed, "addSbtPlugin") || name == ":" || version == "" {
				continue
			}
			scope := "production"
			if strings.Contains(trimmed, "% Test") || strings.Contains(trimmed, "% IntegrationTest") {
				scope = "test"
			}
			k := name + "|" + version + "|" + scope
			if _, ok := seen[k]; ok {
				continue
			}
			seen[k] = struct{}{}
			deps = append(deps, ManifestDependency{ID: uuid.NewString(), ManifestID: manifestID, Name: name, Version: version, Constraint: version, Ecosystem: "maven", Scope: scope, Direct: true})
		}
	}
	return deps
}

func parseSbtPlugins(manifestID, content string) []ManifestDependency {
	lines := strings.Split(content, "\n")
	var deps []ManifestDependency
	seen := map[string]struct{}{}

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "//") {
			continue
		}
		for _, m := range sbtPluginRE.FindAllStringSubmatch(trimmed, -1) {
			name := strings.TrimSpace(m[1]) + ":" + strings.TrimSpace(m[2])
			version := strings.TrimSpace(m[3])
			if name == ":" || version == "" {
				continue
			}
			k := name + "|" + version
			if _, ok := seen[k]; ok {
				continue
			}
			seen[k] = struct{}{}
			deps = append(deps, ManifestDependency{ID: uuid.NewString(), ManifestID: manifestID, Name: name, Version: version, Constraint: version, Ecosystem: "sbt-plugin", Scope: "plugin", Direct: true})
		}
	}
	return deps
}

func parseGradleVersionCatalog(manifestID, content string) []ManifestDependency {
	lines := strings.Split(content, "\n")
	section := ""
	versionMap := map[string]string{}
	var deps []ManifestDependency
	seen := map[string]struct{}{}

	add := func(name, version, ecosystem, scope string, direct bool, constraint string) {
		name = strings.TrimSpace(name)
		version = strings.TrimSpace(version)
		if name == "" {
			return
		}
		if version == "" {
			version = "*"
		}
		k := name + "|" + version + "|" + ecosystem + "|" + scope
		if _, ok := seen[k]; ok {
			return
		}
		seen[k] = struct{}{}
		deps = append(deps, ManifestDependency{ID: uuid.NewString(), ManifestID: manifestID, Name: name, Version: version, Constraint: constraint, Ecosystem: ecosystem, Scope: scope, Direct: direct})
	}

	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.Trim(line, "[]")
			continue
		}
		if !strings.Contains(line, "=") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		switch section {
		case "versions":
			versionMap[key] = strings.Trim(value, `"'`)
		case "libraries":
			module, version, constraint := "", "", ""
			if strings.HasPrefix(value, "{") && strings.HasSuffix(value, "}") {
				body := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(value, "{"), "}"))
				parts := strings.Split(body, ",")
				group, name := "", ""
				for _, p := range parts {
					p = strings.TrimSpace(p)
					pk, pv, ok := strings.Cut(p, "=")
					if !ok {
						continue
					}
					pk = strings.TrimSpace(pk)
					pv = strings.Trim(strings.TrimSpace(pv), `"'`)
					switch pk {
					case "module":
						module = pv
					case "group":
						group = pv
					case "name":
						name = pv
					case "version":
						version = pv
						constraint = pv
					case "version.ref":
						version = versionMap[pv]
						if version == "" {
							version = pv
						}
						constraint = version
					}
				}
				if module == "" && group != "" && name != "" {
					module = group + ":" + name
				}
			}
			if module != "" {
				add(module, version, "maven", "catalog", true, constraint)
			}
		case "plugins":
			if strings.HasPrefix(value, "{") && strings.HasSuffix(value, "}") {
				body := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(value, "{"), "}"))
				parts := strings.Split(body, ",")
				id, version := "", ""
				for _, p := range parts {
					p = strings.TrimSpace(p)
					pk, pv, ok := strings.Cut(p, "=")
					if !ok {
						continue
					}
					pk = strings.TrimSpace(pk)
					pv = strings.Trim(strings.TrimSpace(pv), `"'`)
					switch pk {
					case "id":
						id = pv
					case "version":
						version = pv
					case "version.ref":
						version = versionMap[pv]
						if version == "" {
							version = pv
						}
					}
				}
				if id != "" {
					add(id, version, "gradle-plugin", "catalog-plugin", true, version)
				}
			}
		}
	}
	return deps
}

func extractXMLValue(line, tag string) string {
	start := strings.Index(line, ">")
	end := strings.Index(line, "</"+tag+">")
	if start != -1 && end != -1 && end > start {
		return strings.TrimSpace(line[start+1 : end])
	}
	return ""
}
