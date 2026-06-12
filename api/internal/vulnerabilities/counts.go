package vulnerabilities

import (
	"context"
	"strings"

	"gorm.io/gorm"
)

// CountByVersion returns the number of known vulnerabilities per version
// of a package, combining image-scanner findings (matched by package
// name) and cached OSV results (matched by versioned PURL). Sentinel
// "_none" cache rows are excluded. Errors are swallowed — the counts
// drive a warning indicator, not authoritative data — so a failed query
// just yields zeros.
func CountByVersion(ctx context.Context, db *gorm.DB, basePURL, name string, versions []string) map[string]int {
	out := make(map[string]int, len(versions))
	if len(versions) == 0 {
		return out
	}
	wanted := make(map[string]struct{}, len(versions))
	for _, v := range versions {
		wanted[v] = struct{}{}
	}

	// version -> set of vuln ids, so a CVE present in both sources
	// counts once.
	ids := make(map[string]map[string]struct{}, len(versions))
	add := func(version, vulnID string) {
		if _, ok := wanted[version]; !ok {
			return
		}
		if ids[version] == nil {
			ids[version] = make(map[string]struct{})
		}
		ids[version][vulnID] = struct{}{}
	}

	names := []string{name}
	if i := strings.LastIndex(name, "/"); i >= 0 && name[i+1:] != "" {
		names = append(names, name[i+1:])
	}
	var scanRows []struct {
		InstalledVersion string
		VulnID           string
	}
	if err := db.WithContext(ctx).Raw(`
		SELECT DISTINCT installed_version, vuln_id
		FROM image_vuln_findings
		WHERE pkg_name IN ? AND installed_version IN ?`, names, versions).
		Scan(&scanRows).Error; err == nil {
		for _, r := range scanRows {
			add(r.InstalledVersion, r.VulnID)
		}
	}

	if basePURL != "" {
		var cacheRows []struct {
			PURL   string `gorm:"column:purl"`
			VulnID string
		}
		pattern := likeEscaper.Replace(basePURL) + "@%"
		if err := db.WithContext(ctx).Raw(`
			SELECT purl, vuln_id
			FROM component_vulnerabilities
			WHERE vuln_id <> '_none' AND purl LIKE ?`, pattern).
			Scan(&cacheRows).Error; err == nil {
			for _, r := range cacheRows {
				add(purlVersion(r.PURL), r.VulnID)
			}
		}
	}

	for v, set := range ids {
		out[v] = len(set)
	}
	return out
}

var likeEscaper = strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
