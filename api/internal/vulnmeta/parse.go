package vulnmeta

import (
	"context"
	"encoding/json"
	"regexp"
	"strconv"
	"strings"

	"gorm.io/gorm"
)

// Aliases extracts the aliases array from a stored metadata row. Used
// wherever a handler needs to show cross-references or widen an
// identity match to include every alias an advisory publishes. Returns
// an empty slice on nil meta / malformed JSON so callers can iterate
// without a nil check.
func Aliases(meta *Metadata) []string {
	if meta == nil || len(meta.Aliases) == 0 {
		return nil
	}
	var out []string
	if err := json.Unmarshal(meta.Aliases, &out); err != nil {
		return nil
	}
	return out
}

// AliasSet returns the set of vuln_ids equivalent to the requested one
// (including the requested id itself). Empty aliases on the metadata
// row — or a nil meta — collapse to just the requested id, so callers
// don't need to branch.
func AliasSet(vulnID string, meta *Metadata) []string {
	out := []string{vulnID}
	seen := map[string]struct{}{vulnID: {}}
	for _, a := range Aliases(meta) {
		if a == "" {
			continue
		}
		if _, ok := seen[a]; ok {
			continue
		}
		seen[a] = struct{}{}
		out = append(out, a)
	}
	return out
}

// AliasesForMany pulls the aliases JSONB for a batch of vuln_ids in
// one query. Returns a map keyed by vuln_id so callers can attach the
// result to their own response rows. IDs without an enrichment row
// are simply absent from the map.
//
// Used by the list endpoint to surface cross-references per group
// without running N queries over the page.
func AliasesForMany(ctx context.Context, db *gorm.DB, vulnIDs []string) (map[string][]string, error) {
	if len(vulnIDs) == 0 {
		return map[string][]string{}, nil
	}
	type row struct {
		VulnID  string `gorm:"column:vuln_id"`
		Aliases []byte `gorm:"column:aliases"`
	}
	var rows []row
	if err := db.WithContext(ctx).
		Raw(`SELECT vuln_id, aliases FROM vuln_metadata WHERE vuln_id IN ?`, vulnIDs).
		Scan(&rows).Error; err != nil {
		return nil, err
	}
	out := make(map[string][]string, len(rows))
	for _, r := range rows {
		var aliases []string
		if len(r.Aliases) > 0 {
			_ = json.Unmarshal(r.Aliases, &aliases)
		}
		out[r.VulnID] = aliases
	}
	return out, nil
}

// SearchIDsByAlias returns the set of vuln_ids whose aliases JSONB
// contains the given substring (case-insensitive). Used by the list
// endpoint so typing "CVE" into the search box also surfaces rows
// stored under BIT- / GHSA- / PYSEC- prefixes whose aliases point at
// a CVE id.
//
// Input is not anchored or quoted — the caller should already have
// restricted the needle to a reasonable shape (the list handler
// bounds it to the user's ?q value, which is length-limited
// upstream).
func SearchIDsByAlias(ctx context.Context, db *gorm.DB, needle string) ([]string, error) {
	needle = strings.TrimSpace(needle)
	if needle == "" {
		return nil, nil
	}
	var ids []string
	if err := db.WithContext(ctx).Raw(
		`SELECT vuln_id FROM vuln_metadata WHERE LOWER(aliases::text) LIKE ?`,
		"%"+strings.ToLower(needle)+"%",
	).Scan(&ids).Error; err != nil {
		return nil, err
	}
	return ids, nil
}

// osvAffectedPackage / osvRange / osvEvent capture the subset of the
// OSV schema needed to re-derive an applicable fix version per asset.
// Cached rows' raw_json column holds the OSV payload under key "osv";
// we parse lazily on each request rather than storing a structured
// shape, since OSV keeps evolving and we don't want migrations every
// time a field appears.
type osvAffectedPackage struct {
	Package struct {
		Name      string `json:"name"`
		Ecosystem string `json:"ecosystem"`
		PURL      string `json:"purl"`
	} `json:"package"`
	Ranges []osvRange `json:"ranges"`
}

type osvRange struct {
	Type   string     `json:"type"`
	Events []osvEvent `json:"events"`
}

type osvEvent struct {
	Introduced   string `json:"introduced,omitempty"`
	Fixed        string `json:"fixed,omitempty"`
	LastAffected string `json:"last_affected,omitempty"`
}

// ExtractOSVAffected pulls the `affected[]` list out of the cached
// OSV raw JSON. Returns nil when no OSV payload is stored — callers
// fall back to whichever fix the scanner reported.
func ExtractOSVAffected(meta *Metadata) []osvAffectedPackage {
	if meta == nil || len(meta.RawJSON) == 0 {
		return nil
	}
	var wrapper map[string]json.RawMessage
	if err := json.Unmarshal(meta.RawJSON, &wrapper); err != nil {
		return nil
	}
	osvRaw, ok := wrapper["osv"]
	if !ok || len(osvRaw) == 0 {
		return nil
	}
	var payload struct {
		Affected []osvAffectedPackage `json:"affected"`
	}
	if err := json.Unmarshal(osvRaw, &payload); err != nil {
		return nil
	}
	return payload.Affected
}

// ApplicableFix walks OSV's affected[] → ranges[] → events list and
// returns the "fixed" version of the interval that contains the
// installed version. Returns "" on no match — callers fall back to
// the scanner-reported fixed_version.
//
// Why this exists: grype and trivy occasionally surface the first
// range's fix on multi-interval advisories (valkey 8.1.3-0 getting
// fix=7.2.11 from introduced=0/fixed=7.2.11 when the applicable
// interval is introduced=8.1.0/fixed=8.1.4). This re-derives the
// correct one from the authoritative OSV data.
func ApplicableFix(affected []osvAffectedPackage, pkgName, installed string) string {
	pkgName = strings.TrimSpace(pkgName)
	installed = strings.TrimSpace(installed)
	if pkgName == "" || installed == "" || len(affected) == 0 {
		return ""
	}
	for _, a := range affected {
		if !strings.EqualFold(a.Package.Name, pkgName) {
			continue
		}
		for _, rng := range a.Ranges {
			// Events alternate: introduced, fixed, introduced, fixed.
			// Close an interval on each "fixed" event; reset on the
			// next "introduced". last_affected is a soft upper bound
			// treated as inclusive lower of the next range.
			var introduced string
			for _, ev := range rng.Events {
				if ev.Introduced != "" {
					introduced = ev.Introduced
					continue
				}
				if ev.Fixed != "" {
					if inInterval(installed, introduced, ev.Fixed) {
						return ev.Fixed
					}
					introduced = ""
				}
			}
		}
	}
	return ""
}

// inInterval reports whether installed ∈ [introduced, fixed). "0" or
// empty introduced means "from the beginning", so any installed
// matches the lower bound.
func inInterval(installed, introduced, fixed string) bool {
	if introduced != "" && introduced != "0" && cmpVersion(installed, introduced) < 0 {
		return false
	}
	if cmpVersion(installed, fixed) >= 0 {
		return false
	}
	return true
}

// cmpVersion is a tolerant comparator for common version schemes —
// dotted-numeric (1.2.3), semver with pre-release (1.2.3-rc.1),
// distro suffixes (8.1.3-0), and mixed alphanumeric tokens. Not a
// strict SemVer 2.0 implementation; good enough for range-membership
// decisions on OSV-reported ranges.
//
//   - Numeric vs numeric: integer compare.
//   - Numeric vs alpha: alpha loses (pre-release < release), so
//     "1.0.0-rc" < "1.0.0".
//   - Alpha vs alpha: lexicographic.
//
// Returns -1, 0, 1.
func cmpVersion(a, b string) int {
	ap := splitVersion(a)
	bp := splitVersion(b)
	n := len(ap)
	if len(bp) > n {
		n = len(bp)
	}
	for i := 0; i < n; i++ {
		var ac, bc string
		if i < len(ap) {
			ac = ap[i]
		}
		if i < len(bp) {
			bc = bp[i]
		}
		ai, aerr := strconv.Atoi(ac)
		bi, berr := strconv.Atoi(bc)
		switch {
		case aerr == nil && berr == nil:
			if ai != bi {
				if ai < bi {
					return -1
				}
				return 1
			}
		case aerr == nil && berr != nil:
			// "1.0.0" vs "1.0.0-rc": trailing release outranks the
			// pre-release token. Empty component is the shorter side.
			if bc == "" {
				return 1
			}
			return 1
		case aerr != nil && berr == nil:
			if ac == "" {
				return -1
			}
			return -1
		default:
			if ac != bc {
				if ac < bc {
					return -1
				}
				return 1
			}
		}
	}
	return 0
}

var versionSplitRe = regexp.MustCompile(`[.\-+_]`)

// splitVersion tokenizes on ., -, +, _. Covers semver
// (major.minor.patch[-pre][+build]), distro-style (8.1.3-0), and
// underscored builds.
func splitVersion(v string) []string {
	v = strings.TrimSpace(v)
	if v == "" {
		return nil
	}
	v = strings.TrimPrefix(v, "v")
	return versionSplitRe.Split(v, -1)
}
