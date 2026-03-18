package secretprobe

import (
	"crypto/sha256"
	"fmt"
	"regexp"
	"strings"
)

// SecretHash returns the SHA-256 hex digest of a secret value.
func SecretHash(secret string) string {
	h := sha256.Sum256([]byte(secret))
	return fmt.Sprintf("%x", h)
}

// Common patterns for extracting the actual secret from a gitleaks match string.
// Gitleaks matches often include context like "key = <secret>" or "token: <secret>".
var extractors = []*regexp.Regexp{
	// key = "value" or key := "value"
	regexp.MustCompile(`:=?\s*["']([^"']+)["']`),
	// key: value (YAML/header style)
	regexp.MustCompile(`:\s+(\S+)\s*$`),
	// key=value (bare assignment)
	regexp.MustCompile(`=\s*["']?([^\s"']+)["']?`),
}

// keyExtractors pull the key name (left-hand side) from a match string.
var keyExtractors = []*regexp.Regexp{
	// "KEY_NAME": "value" or KEY_NAME": "value" (JSON-style)
	regexp.MustCompile(`(?:^|[\s{,])["']?([A-Za-z_][A-Za-z0-9_.-]*)["']?\s*:=?\s*["']`),
	// key: value (YAML/header style)
	regexp.MustCompile(`(?:^|[\s])([A-Za-z_][A-Za-z0-9_.-]*):\s+\S`),
	// key=value (bare assignment)
	regexp.MustCompile(`(?:^|[\s])([A-Za-z_][A-Za-z0-9_.-]*)=`),
}

// ExtractSecret tries to pull the actual secret value out of a gitleaks match
// string. Falls back to the full match if no pattern matches.
func ExtractSecret(match string) string {
	s := strings.TrimSpace(match)
	// Strip trailing quote if unbalanced
	if strings.HasSuffix(s, `"`) && strings.Count(s, `"`) == 1 {
		s = s[:len(s)-1]
	}

	for _, re := range extractors {
		if m := re.FindStringSubmatch(s); len(m) > 1 {
			return strings.TrimSpace(m[1])
		}
	}
	return s
}

// ExtractKeyName tries to pull the key/variable name from a gitleaks match
// string. For multi-line strings (e.g. k8s manifests), it works from the last
// line backwards so that it finds the key holding the actual secret rather than
// a structural key like "kind".
//
// Examples:
//
//	"WEB_PUSH_VAPID_PRIVATE_KEY": "SFco..." -> "WEB_PUSH_VAPID_PRIVATE_KEY"
//	"X-Agent-Token: agt_123"                -> "X-Agent-Token"
//	"password: dG9rZW4xMjM="               -> "password"
//	"kind: Secret\n...\n  password: abc"     -> "password"
func ExtractKeyName(match string) string {
	s := strings.TrimSpace(match)

	// For multi-line input, try lines in reverse order to find the
	// key closest to the actual secret value.
	if strings.Contains(s, "\n") {
		lines := strings.Split(s, "\n")
		for i := len(lines) - 1; i >= 0; i-- {
			line := strings.TrimSpace(lines[i])
			if line == "" {
				continue
			}
			for _, re := range keyExtractors {
				if m := re.FindStringSubmatch(line); len(m) > 1 {
					return strings.TrimSpace(m[1])
				}
			}
		}
		return ""
	}

	for _, re := range keyExtractors {
		if m := re.FindStringSubmatch(s); len(m) > 1 {
			return strings.TrimSpace(m[1])
		}
	}
	return ""
}
