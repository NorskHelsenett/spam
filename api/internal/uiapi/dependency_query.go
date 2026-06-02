package uiapi

import (
	"fmt"
	"strconv"
	"strings"
)

type dependencySearchClause struct {
	Name        string
	Comparator  string // "", "=", "<=", "<", ">=", ">"
	RawVersion  string
	Semver      *semverSpec
	UpperRaw    string
	UpperSemver *semverSpec
}

type semverSpec struct {
	Major int
	Minor int
	Patch int
	Parts int // 1,2,3 as provided by the user
}

type parsedDependencySearch struct {
	Structured bool
	Groups     [][]dependencySearchClause // OR groups containing AND clauses
}

func parseDependencySearchQuery(q string) (parsedDependencySearch, error) {
	q = strings.TrimSpace(q)
	if q == "" {
		return parsedDependencySearch{}, nil
	}

	orClauses := splitOrClauses(q)
	if len(orClauses) == 0 {
		return parsedDependencySearch{}, nil
	}

	structured := strings.Contains(q, "||") || strings.Contains(q, "&&")
	groups := make([][]dependencySearchClause, 0, len(orClauses))

	for _, orRaw := range orClauses {
		andClauses := splitAndClauses(orRaw)
		if len(andClauses) == 0 {
			continue
		}
		if len(andClauses) > 1 {
			structured = true
		}

		group := make([]dependencySearchClause, 0, len(andClauses))
		for _, raw := range andClauses {
			clause, usedStructured, err := parseDependencyClause(raw)
			if err != nil {
				return parsedDependencySearch{}, err
			}
			if usedStructured {
				structured = true
			}
			group = append(group, clause)
		}
		groups = append(groups, group)
	}

	if !structured {
		// Keep legacy fuzzy behavior for plain single-token searches.
		return parsedDependencySearch{}, nil
	}

	return parsedDependencySearch{Structured: true, Groups: groups}, nil
}

func splitOrClauses(q string) []string {
	parts := strings.Split(q, "||")
	clauses := make([]string, 0, len(parts))
	for _, part := range parts {
		clause := strings.TrimSpace(part)
		if clause == "" {
			continue
		}
		clauses = append(clauses, clause)
	}
	return clauses
}

func splitAndClauses(q string) []string {
	parts := strings.Split(q, "&&")
	clauses := make([]string, 0, len(parts))
	for _, part := range parts {
		clause := strings.TrimSpace(part)
		if clause == "" {
			continue
		}
		clauses = append(clauses, clause)
	}
	return clauses
}

func parseDependencyClause(raw string) (dependencySearchClause, bool, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return dependencySearchClause{}, false, fmt.Errorf("empty search clause")
	}

	if name, op, version, ok := splitComparatorClause(raw); ok {
		if name == "" || version == "" {
			return dependencySearchClause{}, false, fmt.Errorf("invalid clause %q", raw)
		}
		sv, svErr := parseStrictSemver(version)
		if svErr != nil {
			return dependencySearchClause{}, false, fmt.Errorf("%s in clause %q", svErr.Error(), raw)
		}
		return dependencySearchClause{Name: name, Comparator: op, RawVersion: version, Semver: &sv}, true, nil
	}

	if name, lower, upper, ok := splitBetweenClause(raw); ok {
		if name == "" || lower == "" || upper == "" {
			return dependencySearchClause{}, false, fmt.Errorf("invalid clause %q", raw)
		}
		lowSV, lowErr := parseStrictSemver(lower)
		if lowErr != nil {
			return dependencySearchClause{}, false, fmt.Errorf("%s in clause %q", lowErr.Error(), raw)
		}
		highSV, highErr := parseStrictSemver(upper)
		if highErr != nil {
			return dependencySearchClause{}, false, fmt.Errorf("%s in clause %q", highErr.Error(), raw)
		}
		if compareSemver(lowSV, highSV) > 0 {
			return dependencySearchClause{}, false, fmt.Errorf("invalid range in clause %q: lower bound is greater than upper bound", raw)
		}
		return dependencySearchClause{
			Name:        name,
			Comparator:  "between",
			RawVersion:  lower,
			Semver:      &lowSV,
			UpperRaw:    upper,
			UpperSemver: &highSV,
		}, true, nil
	}

	if name, version, ok := splitAtVersionClause(raw); ok {
		if name == "" || version == "" {
			return dependencySearchClause{}, false, fmt.Errorf("invalid clause %q", raw)
		}
		clause := dependencySearchClause{Name: name, Comparator: "=", RawVersion: version}
		if sv, err := parseStrictSemver(version); err == nil {
			clause.Semver = &sv
		}
		return clause, true, nil
	}

	// Bare package name (used with || to search multiple packages exactly).
	return dependencySearchClause{Name: raw}, false, nil
}

func splitBetweenClause(raw string) (name, lower, upper string, ok bool) {
	idx := strings.Index(raw, "..")
	if idx < 0 {
		return "", "", "", false
	}
	left := strings.TrimSpace(raw[:idx])
	right := strings.TrimSpace(raw[idx+2:])
	if left == "" || right == "" {
		return "", "", "", false
	}

	if at := strings.LastIndex(left, "@"); at > 0 {
		name = strings.TrimSpace(left[:at])
		lower = strings.TrimSpace(left[at+1:])
		upper = right
		if name != "" && lower != "" && upper != "" {
			return name, lower, upper, true
		}
		return "", "", "", false
	}

	fields := strings.Fields(left)
	if len(fields) == 2 {
		name = strings.TrimSpace(fields[0])
		lower = strings.TrimSpace(fields[1])
		upper = right
		if name != "" && lower != "" && upper != "" {
			return name, lower, upper, true
		}
	}

	return "", "", "", false
}

func splitComparatorClause(raw string) (name, op, version string, ok bool) {
	operators := []string{"<=", ">=", "<", ">", "="}
	for _, candidate := range operators {
		idx := strings.Index(raw, candidate)
		if idx < 0 {
			continue
		}
		left := strings.TrimSpace(raw[:idx])
		right := strings.TrimSpace(raw[idx+len(candidate):])
		if left == "" || right == "" {
			return "", "", "", false
		}
		return left, candidate, right, true
	}
	return "", "", "", false
}

func splitAtVersionClause(raw string) (name, version string, ok bool) {
	idx := strings.LastIndex(raw, "@")
	if idx <= 0 || idx >= len(raw)-1 {
		return "", "", false
	}
	left := strings.TrimSpace(raw[:idx])
	right := strings.TrimSpace(raw[idx+1:])
	if left == "" || right == "" || strings.ContainsAny(right, " \t") {
		return "", "", false
	}
	return left, right, true
}

func parseStrictSemver(version string) (semverSpec, error) {
	version = strings.TrimSpace(version)
	version = strings.TrimPrefix(version, "v")
	version = strings.TrimRight(version, ".")
	if version == "" {
		return semverSpec{}, fmt.Errorf("version is empty")
	}

	parts := strings.Split(version, ".")
	if len(parts) < 1 || len(parts) > 3 {
		return semverSpec{}, fmt.Errorf("version %q must be semver-like (major[.minor[.patch]])", version)
	}

	parsed := []int{0, 0, 0}
	for i, p := range parts {
		if p == "" {
			return semverSpec{}, fmt.Errorf("version %q is invalid", version)
		}
		n, err := strconv.Atoi(p)
		if err != nil {
			return semverSpec{}, fmt.Errorf("version %q must be numeric for range operators", version)
		}
		if n < 0 {
			return semverSpec{}, fmt.Errorf("version %q is invalid", version)
		}
		parsed[i] = n
	}

	return semverSpec{Major: parsed[0], Minor: parsed[1], Patch: parsed[2], Parts: len(parts)}, nil
}

func buildStructuredDependencyPredicate(nameCol, versionCol string, groups [][]dependencySearchClause) (string, []interface{}) {
	orParts := make([]string, 0, len(groups))
	args := make([]interface{}, 0, len(groups)*8)

	for _, group := range groups {
		andParts := make([]string, 0, len(group))
		for _, clause := range group {
			// Match on the bare column expression (no COALESCE wrapper, no
			// LOWER(col)=? branch) so the pg_trgm functional indexes defined on
			// exactly COALESCE(package_name, normalized_name, name) and md.name
			// stay eligible. Wrapping the column or OR-ing in a case-folded
			// equality forces a full materialized-view seq scan, which 504s once
			// a multi-package `a || b || c ...` search fans out across clauses.
			// ILIKE '%name%' is already case-insensitive and subsumes the exact
			// match, so the result set is unchanged.
			nameMatch := fmt.Sprintf("(%s ILIKE ?)", nameCol)
			args = append(args, "%"+clause.Name+"%")

			if clause.Comparator == "" || clause.RawVersion == "" {
				andParts = append(andParts, "("+nameMatch+")")
				continue
			}

			versionExpr := semverTupleExpr(versionCol)
			validSemverExpr := semverValidExpr(versionCol)

			if clause.Comparator == "between" {
				low := *clause.Semver
				high := *clause.UpperSemver
				andParts = append(andParts, "("+nameMatch+" AND "+validSemverExpr+" AND "+versionExpr+" >= ROW(?, ?, ?) AND "+versionExpr+" <= ROW(?, ?, ?))")
				args = append(args, low.Major, low.Minor, low.Patch, high.Major, high.Minor, high.Patch)
				continue
			}

			if clause.Semver == nil {
				// Non-semver exact match fallback.
				andParts = append(andParts, "("+nameMatch+" AND LOWER(COALESCE("+versionCol+", '')) = LOWER(?))")
				args = append(args, clause.RawVersion)
				continue
			}

			op, major, minor, patch := semverComparatorTarget(clause.Comparator, *clause.Semver)
			andParts = append(andParts, "("+nameMatch+" AND "+validSemverExpr+" AND "+versionExpr+" "+op+" ROW(?, ?, ?))")
			args = append(args, major, minor, patch)
		}

		if len(andParts) > 0 {
			orParts = append(orParts, "("+strings.Join(andParts, " AND ")+")")
		}
	}

	if len(orParts) == 0 {
		return "", nil
	}

	return "(" + strings.Join(orParts, " OR ") + ")", args
}

func semverComparatorTarget(op string, sv semverSpec) (string, int, int, int) {
	major, minor, patch := sv.Major, sv.Minor, sv.Patch

	switch op {
	case "<=":
		if sv.Parts == 1 {
			return "<", major + 1, 0, 0
		}
		if sv.Parts == 2 {
			return "<", major, minor + 1, 0
		}
		return "<=", major, minor, patch
	case "<":
		if sv.Parts == 1 {
			return "<", major, 0, 0
		}
		if sv.Parts == 2 {
			return "<", major, minor, 0
		}
		return "<", major, minor, patch
	case ">=":
		if sv.Parts == 1 {
			return ">=", major, 0, 0
		}
		if sv.Parts == 2 {
			return ">=", major, minor, 0
		}
		return ">=", major, minor, patch
	case ">":
		if sv.Parts == 1 {
			return ">", major, 0, 0
		}
		if sv.Parts == 2 {
			return ">", major, minor, 0
		}
		return ">", major, minor, patch
	default:
		// Exact or @ syntax.
		return "=", major, minor, patch
	}
}

func semverValidExpr(versionCol string) string {
	major := "NULLIF(substring(COALESCE(" + versionCol + ", '') from '^v{0,1}([0-9]+)'), '')"
	return major + " IS NOT NULL"
}

func semverTupleExpr(versionCol string) string {
	major := "COALESCE(NULLIF(substring(COALESCE(" + versionCol + ", '') from '^v{0,1}([0-9]+)'), '')::int, 0)"
	minor := "COALESCE(NULLIF(substring(COALESCE(" + versionCol + ", '') from '^v{0,1}[0-9]+\\.([0-9]+)'), '')::int, 0)"
	patch := "COALESCE(NULLIF(substring(COALESCE(" + versionCol + ", '') from '^v{0,1}[0-9]+\\.[0-9]+\\.([0-9]+)'), '')::int, 0)"
	return "ROW(" + major + ", " + minor + ", " + patch + ")"
}

func compareSemver(a, b semverSpec) int {
	if a.Major != b.Major {
		if a.Major < b.Major {
			return -1
		}
		return 1
	}
	if a.Minor != b.Minor {
		if a.Minor < b.Minor {
			return -1
		}
		return 1
	}
	if a.Patch != b.Patch {
		if a.Patch < b.Patch {
			return -1
		}
		return 1
	}
	return 0
}
