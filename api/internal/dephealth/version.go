package dephealth

import (
	"strconv"
	"strings"
)

// VersionsBehind compares an installed version against the registry's
// latest and returns (major, minor, patch) deltas. Negative deltas
// (installed > latest, e.g. a fork ahead of upstream) clamp to zero —
// they're not actionable signals.
//
// Non-semver inputs degrade gracefully: PEP 440-style "1.0.0a1" or
// crate "0.5.0-pre" are stripped to their canonical core ("1.0.0",
// "0.5.0"). When either side is unparseable we return zeros — better
// to under-report than to falsely accuse a package of being years
// behind.
func VersionsBehind(installed, latest string) (int, int, int) {
	iMaj, iMin, iPatch, ok1 := parseSemverCore(installed)
	lMaj, lMin, lPatch, ok2 := parseSemverCore(latest)
	if !ok1 || !ok2 {
		return 0, 0, 0
	}

	major := lMaj - iMaj
	if major > 0 {
		return major, 0, 0
	}
	if major < 0 {
		return 0, 0, 0
	}

	minor := lMin - iMin
	if minor > 0 {
		return 0, minor, 0
	}
	if minor < 0 {
		return 0, 0, 0
	}

	patch := lPatch - iPatch
	if patch > 0 {
		return 0, 0, patch
	}
	return 0, 0, 0
}

// parseSemverCore extracts the (major, minor, patch) integer triple
// from a version string. Strips common prefix decorators (v, ^, ~,
// >=, =, etc.) and pre-release / build metadata. Returns ok=false
// when there's no recognisable major segment — caller treats that
// as "don't compare".
func parseSemverCore(s string) (int, int, int, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, 0, 0, false
	}

	// Strip leading constraint operators (npm range syntax, etc.).
	s = strings.TrimLeft(s, "^~=>!<")
	s = strings.TrimSpace(s)

	// Strip leading 'v' or 'V'.
	if len(s) > 0 && (s[0] == 'v' || s[0] == 'V') {
		s = s[1:]
	}

	// Cut at the first non-version character (anything that's not a
	// digit or dot). Handles "1.0.0-rc1", "1.0.0+build", "1.0.0a1".
	for i, c := range s {
		isDigit := c >= '0' && c <= '9'
		isDot := c == '.'
		if !isDigit && !isDot {
			s = s[:i]
			break
		}
	}
	if s == "" {
		return 0, 0, 0, false
	}

	parts := strings.Split(s, ".")
	if len(parts) == 0 || parts[0] == "" {
		return 0, 0, 0, false
	}
	major, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0, 0, 0, false
	}
	minor, patch := 0, 0
	if len(parts) > 1 && parts[1] != "" {
		if n, err := strconv.Atoi(parts[1]); err == nil {
			minor = n
		}
	}
	if len(parts) > 2 && parts[2] != "" {
		if n, err := strconv.Atoi(parts[2]); err == nil {
			patch = n
		}
	}
	return major, minor, patch, true
}
