package uiapi

import (
	"fmt"
	"strconv"
	"strings"
)

type dependencySearchClause struct {
	Name       string
	Comparator string // "", "=", "<=", "<", ">=", ">"
	RawVersion string
	Semver     *semverSpec
}

type semverSpec struct {
	Major int
	Minor int
	Patch int
	Parts int // 1,2,3 as provided by the user
}

type parsedDependencySearch struct {
	Structured bool
	Clauses    []dependencySearchClause
}

func parseDependencySearchQuery(q string) (parsedDependencySearch, error) {
	q = strings.TrimSpace(q)
	if q == "" {
		return parsedDependencySearch{}, nil
	}

	rawClauses := splitOrClauses(q)
	if len(rawClauses) == 0 {
		return parsedDependencySearch{}, nil
	}

	structured := len(rawClauses) > 1
	clauses := make([]dependencySearchClause, 0, len(rawClauses))

	for _, raw := range rawClauses {
		clause, usedStructured, err := parseDependencyClause(raw)
		if err != nil {
			return parsedDependencySearch{}, err
		}
		if usedStructured {
			structured = true
		}
		clauses = append(clauses, clause)
	}

	if !structured {
		// Keep legacy fuzzy behavior for plain single-token searches.
		return parsedDependencySearch{}, nil
	}

	return parsedDependencySearch{Structured: true, Clauses: clauses}, nil
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

func buildStructuredDependencyPredicate(nameCol, versionCol string, clauses []dependencySearchClause) (string, []interface{}) {
	orParts := make([]string, 0, len(clauses))
	args := make([]interface{}, 0, len(clauses)*5)

	for _, clause := range clauses {
		nameMatch := fmt.Sprintf("(LOWER(COALESCE(%s, '')) = LOWER(?) OR COALESCE(%s, '') ILIKE ?)", nameCol, nameCol)
		args = append(args, clause.Name, "%"+clause.Name+"%")

		if clause.Comparator == "" || clause.RawVersion == "" {
			orParts = append(orParts, "("+nameMatch+")")
			continue
		}

		versionExpr := semverTupleExpr(versionCol)
		validSemverExpr := semverValidExpr(versionCol)

		if clause.Semver == nil {
			// Non-semver exact match fallback.
			orParts = append(orParts, "("+nameMatch+" AND LOWER(COALESCE("+versionCol+", '')) = LOWER(?))")
			args = append(args, clause.RawVersion)
			continue
		}

		op, major, minor, patch := semverComparatorTarget(clause.Comparator, *clause.Semver)
		orParts = append(orParts, "("+nameMatch+" AND "+validSemverExpr+" AND "+versionExpr+" "+op+" ROW(?, ?, ?))")
		args = append(args, major, minor, patch)
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
