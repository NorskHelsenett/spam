package secretprobe

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"strings"
)

// Classification is the result of reclassifying a secret based on its content.
type Classification struct {
	EffectiveRuleID string      `json:"effective_rule_id"` // the rule that best describes this secret
	OriginalRuleID  string      `json:"original_rule_id"`  // the gitleaks rule that matched
	Reclassified    bool        `json:"reclassified"`      // true if the effective rule differs from original
	ProbeOutput     ProbeOutput `json:"probe_output"`      // result of offline probing
}

// Classify inspects a secret's content and returns its true classification.
// It tries base64 decoding, JWT detection, PEM parsing, etc. to determine
// what the secret actually is, regardless of which gitleaks rule matched it.
//
// This never makes network calls — it only does local inspection.
func Classify(secret, ruleID string) Classification {
	c := Classification{
		EffectiveRuleID: ruleID,
		OriginalRuleID:  ruleID,
	}

	// Try to decode the secret from base64 — many secrets are base64-wrapped.
	decoded := tryBase64Decode(secret)

	// 1. Check if the secret (or its decoded form) is a JWT.
	jwtCandidate := secret
	if decoded != "" && looksLikeJWT(decoded) {
		jwtCandidate = decoded
	}
	if looksLikeJWT(jwtCandidate) {
		if ruleID != "jwt" && ruleID != "jwt-base64" {
			c.EffectiveRuleID = "jwt"
			c.Reclassified = true
		}
		c.ProbeOutput = probeJWT(context.Background(), ProbeContext{
			Secret: jwtCandidate,
			RuleID: c.EffectiveRuleID,
		})
		return c
	}

	// 2. For jwt-base64: if it didn't pass the JWT check above, it's not a JWT.
	if ruleID == "jwt-base64" {
		// Try the decoded value as well.
		if decoded != "" && looksLikeJWT(decoded) {
			c.ProbeOutput = probeJWT(context.Background(), ProbeContext{
				Secret: decoded,
				RuleID: ruleID,
			})
			return c
		}
		c.ProbeOutput = ProbeOutput{
			Status: StatusInvalid,
			Reason: "not a valid JWT",
		}
		return c
	}

	// 3. Check if the secret (or decoded form) contains a PEM block.
	pemCandidate := secret
	if decoded != "" && strings.Contains(decoded, "-----BEGIN") {
		pemCandidate = decoded
	}
	if strings.Contains(pemCandidate, "-----BEGIN") {
		c.ProbeOutput = classifyPEM(pemCandidate)
		if c.ProbeOutput.Status != StatusUnknown || ruleID == "private-key" {
			if ruleID != "private-key" {
				c.EffectiveRuleID = "private-key"
				c.Reclassified = true
			}
			return c
		}
	}

	// 4. For private-key rule: if we get here, no PEM block was found.
	if ruleID == "private-key" {
		// Maybe it's base64-encoded PEM.
		if decoded != "" && strings.Contains(decoded, "-----BEGIN") {
			c.ProbeOutput = classifyPEM(decoded)
			return c
		}
		c.ProbeOutput = ProbeOutput{
			Status: StatusInvalid,
			Reason: "no PEM block found",
		}
		return c
	}

	// 5. Default: run the registered offline probe if available.
	p := Lookup(ruleID)
	if p != nil && p.Kind() == ProbeKindOffline {
		c.ProbeOutput = p.Probe(context.Background(), ProbeContext{
			Secret: secret,
			RuleID: ruleID,
		})
		return c
	}

	// No offline classification possible.
	c.ProbeOutput = ProbeOutput{
		Status: StatusUnknown,
		Reason: "no offline classification available",
	}
	return c
}

// tryBase64Decode attempts standard and URL-safe base64 decoding.
// Returns the decoded string if it produces valid UTF-8 text, empty string otherwise.
func tryBase64Decode(s string) string {
	s = strings.TrimSpace(s)
	if len(s) < 8 {
		return ""
	}

	// Skip if it already looks like plain text (PEM, JWT, URL, etc.)
	if strings.HasPrefix(s, "-----") || strings.HasPrefix(s, "eyJ") ||
		strings.HasPrefix(s, "http") || strings.HasPrefix(s, "{") {
		return ""
	}

	// Try standard base64.
	if b, err := base64.StdEncoding.DecodeString(s); err == nil && isValidText(b) {
		return string(b)
	}

	// Try URL-safe base64.
	if b, err := base64.URLEncoding.DecodeString(s); err == nil && isValidText(b) {
		return string(b)
	}

	// Try without padding.
	if b, err := base64.RawStdEncoding.DecodeString(s); err == nil && isValidText(b) {
		return string(b)
	}
	if b, err := base64.RawURLEncoding.DecodeString(s); err == nil && isValidText(b) {
		return string(b)
	}

	return ""
}

// isValidText checks if decoded bytes look like meaningful text (mostly printable ASCII/UTF-8).
func isValidText(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	printable := 0
	for _, c := range b {
		if c >= 0x20 && c < 0x7F || c == '\n' || c == '\r' || c == '\t' {
			printable++
		}
	}
	return float64(printable)/float64(len(b)) > 0.8
}

// classifyPEM parses a PEM block and determines if it's a private key, certificate, etc.
func classifyPEM(s string) ProbeOutput {
	block, _ := pem.Decode([]byte(s))
	if block == nil {
		if idx := strings.Index(s, "-----BEGIN"); idx >= 0 {
			block, _ = pem.Decode([]byte(s[idx:]))
		}
	}
	if block == nil {
		return ProbeOutput{Status: StatusUnknown, Reason: "no PEM block found"}
	}

	meta := map[string]any{"type": block.Type}

	// Certificates are not secrets.
	if strings.Contains(block.Type, "CERTIFICATE") {
		return ProbeOutput{
			Status:   StatusInvalid,
			Reason:   "certificate, not a secret",
			Metadata: meta,
		}
	}

	// Public keys are not secrets.
	if strings.Contains(block.Type, "PUBLIC KEY") {
		return ProbeOutput{
			Status:   StatusInvalid,
			Reason:   "public key, not a secret",
			Metadata: meta,
		}
	}

	// Private keys — validate them.
	switch {
	case strings.Contains(block.Type, "RSA PRIVATE KEY"):
		if _, err := x509.ParsePKCS1PrivateKey(block.Bytes); err != nil {
			meta["parse_error"] = err.Error()
			return ProbeOutput{Status: StatusInvalid, Reason: "malformed RSA key", Metadata: meta}
		}
		return ProbeOutput{Status: StatusValid, Reason: "valid RSA private key", Metadata: meta}

	case strings.Contains(block.Type, "EC PRIVATE KEY"):
		if _, err := x509.ParseECPrivateKey(block.Bytes); err != nil {
			meta["parse_error"] = err.Error()
			return ProbeOutput{Status: StatusInvalid, Reason: "malformed EC key", Metadata: meta}
		}
		return ProbeOutput{Status: StatusValid, Reason: "valid EC private key", Metadata: meta}

	case strings.Contains(block.Type, "PRIVATE KEY"):
		if _, err := x509.ParsePKCS8PrivateKey(block.Bytes); err != nil {
			meta["parse_error"] = err.Error()
			return ProbeOutput{Status: StatusInvalid, Reason: "malformed PKCS8 key", Metadata: meta}
		}
		return ProbeOutput{Status: StatusValid, Reason: "valid PKCS8 private key", Metadata: meta}

	default:
		return ProbeOutput{Status: StatusUnknown, Reason: "unrecognized PEM type: " + block.Type, Metadata: meta}
	}
}
