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
