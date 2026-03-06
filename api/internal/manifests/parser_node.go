package manifests

import (
	"encoding/json"
	"strings"

	"github.com/google/uuid"
	"gopkg.in/yaml.v3"
)

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

func parsePackageLockJSON(manifestID, content string) []ManifestDependency {
	var lock struct {
		Packages map[string]struct {
			Version string `json:"version"`
			Dev     bool   `json:"dev"`
		} `json:"packages"`
		Dependencies map[string]struct {
			Version      string                     `json:"version"`
			Dependencies map[string]json.RawMessage `json:"dependencies"`
			Requires     map[string]json.RawMessage `json:"requires"`
		} `json:"dependencies"`
	}

	if err := json.Unmarshal([]byte(content), &lock); err != nil {
		return nil
	}

	var deps []ManifestDependency
	seen := map[string]struct{}{}

	for pkgPath, pkg := range lock.Packages {
		if pkgPath == "" || pkgPath == "." {
			continue
		}
		if !strings.HasPrefix(pkgPath, "node_modules/") {
			continue
		}
		name := strings.TrimPrefix(pkgPath, "node_modules/")
		if name == "" || pkg.Version == "" {
			continue
		}
		scope := "production"
		if pkg.Dev {
			scope = "development"
		}
		k := name + "|" + pkg.Version + "|" + scope
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}
		deps = append(deps, ManifestDependency{
			ID:         uuid.NewString(),
			ManifestID: manifestID,
			Name:       name,
			Version:    pkg.Version,
			Constraint: pkg.Version,
			Ecosystem:  "npm",
			Scope:      scope,
			Direct:     false,
		})
	}

	if len(deps) > 0 {
		return deps
	}

	var walk func(map[string]struct {
		Version      string                     `json:"version"`
		Dependencies map[string]json.RawMessage `json:"dependencies"`
		Requires     map[string]json.RawMessage `json:"requires"`
	}, bool)

	walk = func(nodes map[string]struct {
		Version      string                     `json:"version"`
		Dependencies map[string]json.RawMessage `json:"dependencies"`
		Requires     map[string]json.RawMessage `json:"requires"`
	}, direct bool) {
		for name, dep := range nodes {
			if name == "" || dep.Version == "" {
				continue
			}
			scope := "production"
			if !direct {
				scope = "transitive"
			}
			k := name + "|" + dep.Version + "|" + scope
			if _, ok := seen[k]; !ok {
				seen[k] = struct{}{}
				deps = append(deps, ManifestDependency{
					ID:         uuid.NewString(),
					ManifestID: manifestID,
					Name:       name,
					Version:    dep.Version,
					Constraint: dep.Version,
					Ecosystem:  "npm",
					Scope:      scope,
					Direct:     direct,
				})
			}
			if len(dep.Dependencies) == 0 {
				continue
			}
			next := map[string]struct {
				Version      string                     `json:"version"`
				Dependencies map[string]json.RawMessage `json:"dependencies"`
				Requires     map[string]json.RawMessage `json:"requires"`
			}{}
			for childName, raw := range dep.Dependencies {
				var child struct {
					Version      string                     `json:"version"`
					Dependencies map[string]json.RawMessage `json:"dependencies"`
					Requires     map[string]json.RawMessage `json:"requires"`
				}
				if err := json.Unmarshal(raw, &child); err == nil {
					next[childName] = child
				}
			}
			walk(next, false)
		}
	}

	if len(lock.Dependencies) > 0 {
		walk(lock.Dependencies, true)
	}
	return deps
}

func parseYarnLock(manifestID, content string) []ManifestDependency {
	lines := strings.Split(content, "\n")
	var deps []ManifestDependency
	seen := map[string]struct{}{}
	currentNames := []string{}

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if !strings.HasPrefix(line, " ") && strings.HasSuffix(trimmed, ":") {
			header := strings.TrimSuffix(trimmed, ":")
			parts := strings.Split(header, ",")
			currentNames = currentNames[:0]
			for _, part := range parts {
				part = strings.Trim(strings.TrimSpace(part), `"'`)
				if name := parseNpmDescriptorName(part); name != "" {
					currentNames = append(currentNames, name)
				}
			}
			continue
		}
		if !strings.HasPrefix(trimmed, "version ") {
			continue
		}
		version := strings.Trim(strings.TrimPrefix(trimmed, "version "), `"'`)
		if version == "" {
			continue
		}
		for _, name := range currentNames {
			k := name + "|" + version
			if _, ok := seen[k]; ok {
				continue
			}
			seen[k] = struct{}{}
			deps = append(deps, ManifestDependency{
				ID:         uuid.NewString(),
				ManifestID: manifestID,
				Name:       name,
				Version:    version,
				Constraint: version,
				Ecosystem:  "npm",
				Scope:      "lockfile",
				Direct:     false,
			})
		}
	}
	return deps
}

func parsePnpmLockYAML(manifestID, content string) []ManifestDependency {
	var doc struct {
		Importers map[string]struct {
			Dependencies         map[string]interface{} `yaml:"dependencies"`
			DevDependencies      map[string]interface{} `yaml:"devDependencies"`
			OptionalDependencies map[string]interface{} `yaml:"optionalDependencies"`
		} `yaml:"importers"`
		Packages map[string]interface{} `yaml:"packages"`
	}
	if err := yaml.Unmarshal([]byte(content), &doc); err != nil {
		return nil
	}

	var deps []ManifestDependency
	seen := map[string]struct{}{}
	add := func(name, version, scope string, direct bool) {
		name = strings.TrimSpace(name)
		version = normalizePnpmVersion(version)
		if name == "" || version == "" {
			return
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
			Ecosystem:  "npm",
			Scope:      scope,
			Direct:     direct,
		})
	}

	for _, imp := range doc.Importers {
		for name, raw := range imp.Dependencies {
			add(name, extractPnpmVersion(raw), "production", true)
		}
		for name, raw := range imp.DevDependencies {
			add(name, extractPnpmVersion(raw), "development", true)
		}
		for name, raw := range imp.OptionalDependencies {
			add(name, extractPnpmVersion(raw), "optional", true)
		}
	}

	for key := range doc.Packages {
		name, version := parsePnpmPackageKey(key)
		add(name, version, "lockfile", false)
	}

	return deps
}

func parseBunLock(manifestID, content string) []ManifestDependency {
	return parseYarnLock(manifestID, content)
}

func parseNpmDescriptorName(descriptor string) string {
	descriptor = strings.TrimSpace(descriptor)
	descriptor = strings.Trim(descriptor, `"'`)
	if descriptor == "" {
		return ""
	}
	if idx := strings.Index(descriptor, "npm:"); idx != -1 {
		descriptor = descriptor[idx+4:]
	}
	at := strings.LastIndex(descriptor, "@")
	if at <= 0 {
		return descriptor
	}
	return descriptor[:at]
}

func parsePnpmPackageKey(key string) (string, string) {
	key = strings.TrimSpace(key)
	key = strings.TrimPrefix(key, "/")
	if key == "" {
		return "", ""
	}
	parts := strings.SplitN(key, "(", 2)
	base := parts[0]
	at := strings.LastIndex(base, "@")
	if at <= 0 {
		return "", ""
	}
	name := base[:at]
	version := base[at+1:]
	return name, normalizePnpmVersion(version)
}

func extractPnpmVersion(raw interface{}) string {
	switch v := raw.(type) {
	case string:
		return normalizePnpmVersion(v)
	case map[string]interface{}:
		if s, ok := v["version"].(string); ok {
			return normalizePnpmVersion(s)
		}
	}
	return ""
}

func normalizePnpmVersion(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return v
	}
	if idx := strings.Index(v, "("); idx != -1 {
		v = v[:idx]
	}
	v = strings.TrimPrefix(v, "npm:")
	return strings.TrimSpace(v)
}
