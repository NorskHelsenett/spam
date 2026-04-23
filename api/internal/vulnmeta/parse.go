package vulnmeta

import (
	"context"
	"encoding/json"
	"regexp"
	"strconv"
	"strings"

	"gorm.io/gorm"
)

// canonicalPrefixPriority orders alias prefixes so the "canonical"
// identifier for an advisory is deterministic: CVE first (widest
// cross-ecosystem recognition), then GHSA (GitHub advisories, rich
// content), then BIT (Bitnami feed) and OSV (generic fallback). Any
// id not matching these prefixes falls through to the self id.
var canonicalPrefixPriority = []string{"CVE-", "GHSA-", "BIT-", "OSV-"}

// PickCanonical returns the preferred display / grouping id from an
// alias set. Preference order is canonicalPrefixPriority; within a
// prefix, lexical sort gives a stable pick when an advisory lists
// multiple ids of the same family (rare but legal in OSV).
//
// Falls back to vulnID when no alias matches — so the function is
// total: every caller gets a non-empty result.
func PickCanonical(vulnID string, aliases []string) string {
	// Include vulnID itself in the search set. Scanner-stored rows
	// frequently *are* the canonical, so a nil / short aliases list
	// still yields the right answer.
	candidates := make([]string, 0, len(aliases)+1)
	seen := map[string]struct{}{}
	add := func(s string) {
		if s == "" {
			return
		}
		if _, ok := seen[s]; ok {
			return
		}
		seen[s] = struct{}{}
		candidates = append(candidates, s)
	}
	add(vulnID)
	for _, a := range aliases {
		add(a)
	}
	for _, prefix := range canonicalPrefixPriority {
		var best string
		for _, c := range candidates {
			if !strings.HasPrefix(c, prefix) {
				continue
			}
			if best == "" || c < best {
				best = c
			}
		}
		if best != "" {
			return best
		}
	}
	return vulnID
}

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

// MetadataForMany pulls a batch of metadata rows matching any of the
// given ids against EITHER vuln_id or canonical_id. Callers typically
// pass canonical ids (the list endpoint groups by canonical, the
// detail endpoint resolves requested → canonical). Returns a map
// keyed by canonical_id — when two rows share a canonical (two
// prefixes of the same advisory, both enriched separately), the
// first-seen row wins.
func MetadataForMany(ctx context.Context, db *gorm.DB, ids []string) (map[string]*Metadata, error) {
	if len(ids) == 0 {
		return map[string]*Metadata{}, nil
	}
	var rows []Metadata
	if err := db.WithContext(ctx).
		Where("vuln_id IN ? OR canonical_id IN ?", ids, ids).
		Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make(map[string]*Metadata, len(rows))
	for i := range rows {
		// Key by canonical when present so a group keyed by canonical
		// in the caller's output finds its metadata; fall back to
		// vuln_id for rows predating the canonical_id backfill.
		key := rows[i].CanonicalID
		if key == "" {
			key = rows[i].VulnID
		}
		if _, exists := out[key]; !exists {
			out[key] = &rows[i]
		}
	}
	return out, nil
}

// AliasesByCanonical is a thin wrapper over MetadataForMany that
// returns only the aliases, keyed by canonical_id. Convenience for
// list rendering where the full Metadata isn't needed.
func AliasesByCanonical(ctx context.Context, db *gorm.DB, canonicalIDs []string) (map[string][]string, error) {
	metas, err := MetadataForMany(ctx, db, canonicalIDs)
	if err != nil {
		return nil, err
	}
	out := make(map[string][]string, len(metas))
	for k, m := range metas {
		out[k] = Aliases(m)
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
