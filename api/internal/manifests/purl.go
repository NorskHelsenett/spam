package manifests

import (
	"fmt"
	"net/url"
	"strings"
)

// BuildDependencyPURL converts a manifest dependency into a versioned package URL
// when the dependency carries an exact version. Range-style constraints are
// intentionally skipped to avoid querying OSV with an invented installed version.
func BuildDependencyPURL(dep ManifestDependency) string {
	version := strings.TrimSpace(dep.Version)
	if version == "" || version == "*" {
		return ""
	}
	if !hasExactVersion(dep.Constraint, version) {
		return ""
	}

	switch dep.Ecosystem {
	case "npm":
		return fmt.Sprintf("pkg:npm/%s@%s", escapePath(dep.Name), url.PathEscape(version))
	case "golang":
		return fmt.Sprintf("pkg:golang/%s@%s", escapePath(dep.Name), url.PathEscape(version))
	case "pypi":
		return fmt.Sprintf("pkg:pypi/%s@%s", escapePath(strings.ToLower(dep.Name)), url.PathEscape(version))
	case "nuget":
		return fmt.Sprintf("pkg:nuget/%s@%s", escapePath(dep.Name), url.PathEscape(version))
	case "maven":
		group, artifact, ok := strings.Cut(dep.Name, ":")
		if !ok || strings.TrimSpace(group) == "" || strings.TrimSpace(artifact) == "" {
			return ""
		}
		return fmt.Sprintf("pkg:maven/%s/%s@%s", escapeSegment(group), escapeSegment(artifact), url.PathEscape(version))
	case "cargo":
		return fmt.Sprintf("pkg:cargo/%s@%s", escapePath(dep.Name), url.PathEscape(version))
	case "rubygems":
		return fmt.Sprintf("pkg:gem/%s@%s", escapePath(dep.Name), url.PathEscape(version))
	case "packagist":
		return fmt.Sprintf("pkg:composer/%s@%s", escapePath(dep.Name), url.PathEscape(version))
	default:
		return ""
	}
}

func hasExactVersion(constraint, version string) bool {
	constraint = strings.TrimSpace(constraint)
	if constraint == "" || constraint == version {
		return true
	}

	for _, prefix := range []string{"==", "="} {
		if strings.HasPrefix(constraint, prefix) && strings.TrimSpace(strings.TrimPrefix(constraint, prefix)) == version {
			return true
		}
	}

	return false
}

func escapePath(v string) string {
	parts := strings.Split(strings.TrimSpace(v), "/")
	for i, part := range parts {
		parts[i] = escapeSegment(part)
	}
	return strings.Join(parts, "/")
}

func escapeSegment(v string) string {
	escaped := url.PathEscape(strings.TrimSpace(v))
	return strings.ReplaceAll(escaped, "@", "%40")
}
