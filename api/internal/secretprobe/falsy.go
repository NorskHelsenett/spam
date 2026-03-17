package secretprobe

import (
	"math"
	"strings"
	"unicode"
)

// IsFalsy returns true if the secret looks like a placeholder, test value,
// or otherwise non-real secret. These are marked false_positive without
// any network call.
func IsFalsy(secret string) (bool, string) {
	s := strings.TrimSpace(secret)
	if len(s) == 0 {
		return true, "empty"
	}

	lower := strings.ToLower(s)

	// Known placeholder keywords
	placeholders := []string{
		"example", "changeme", "password", "secret", "dummy",
		"todo", "fixme", "replace", "insert", "your_",
		"xxx", "test", "sample", "placeholder", "fake",
	}
	for _, p := range placeholders {
		if strings.Contains(lower, p) {
			return true, "placeholder: " + p
		}
	}

	// Sequential ASCII (abcdef..., 123456..., AAAAAA...)
	if isSequential(s) {
		return true, "sequential pattern"
	}

	// All same character
	if isRepeated(s) {
		return true, "repeated character"
	}

	// Very low entropy (< 2.0 bits for strings > 16 chars)
	if len(s) > 16 && shannonEntropy(s) < 2.0 {
		return true, "low entropy"
	}

	return false, ""
}

func isSequential(s string) bool {
	if len(s) < 8 {
		return false
	}
	ascending, descending := 0, 0
	for i := 1; i < len(s); i++ {
		if s[i] == s[i-1]+1 {
			ascending++
		} else if s[i] == s[i-1]-1 {
			descending++
		}
	}
	threshold := len(s) * 70 / 100
	return ascending >= threshold || descending >= threshold
}

func isRepeated(s string) bool {
	if len(s) < 6 {
		return false
	}
	for _, r := range s[1:] {
		if r != rune(s[0]) && !unicode.IsSpace(r) {
			return false
		}
	}
	return true
}

func shannonEntropy(s string) float64 {
	freq := map[rune]float64{}
	for _, r := range s {
		freq[r]++
	}
	n := float64(len([]rune(s)))
	entropy := 0.0
	for _, count := range freq {
		p := count / n
		if p > 0 {
			entropy -= p * math.Log2(p)
		}
	}
	return entropy
}
