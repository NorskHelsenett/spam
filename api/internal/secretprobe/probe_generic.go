package secretprobe

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"strings"
)

func init() {
	// generic-api-key is the most common gitleaks rule. We can't probe it
	// over the network (we don't know which service it belongs to), but we
	// can run offline checks: falsy detection + entropy are already handled
	// by the runner. This probe marks surviving secrets as "unknown" with
	// a note that manual review is needed.
	RegisterOffline("generic-api-key", probeGenericAPIKey)
	RegisterOffline("private-key", probePrivateKey)
	RegisterOffline("gcp-api-key", probeGenericAPIKey)
	RegisterOffline("kubernetes-secret-yaml", probeKubernetesSecret)
	RegisterOffline("curl-auth-header", probeGenericAPIKey)
}

func probeGenericAPIKey(ctx context.Context, pc ProbeContext) ProbeOutput {
	// If the secret looks like a JWT, delegate to JWT probe for expiry checks.
	if looksLikeJWT(pc.Secret) {
		return probeJWT(ctx, pc)
	}

	// Falsy check already ran in the runner. If we get here, the secret
	// passed entropy/placeholder checks. We can't validate it without
	// knowing the target service — mark as unknown for manual review.
	return ProbeOutput{
		Status: StatusUnknown,
		Reason: "generic secret — manual review needed",
	}
}

// looksLikeJWT returns true if s has the shape of a JWT: three dot-separated
// parts where the first starts with "eyJ" (base64 for '{"').
func looksLikeJWT(s string) bool {
	if !strings.HasPrefix(s, "eyJ") {
		return false
	}
	parts := strings.SplitN(s, ".", 4)
	return len(parts) == 3 && len(parts[0]) > 3 && len(parts[1]) > 3
}

func probePrivateKey(_ context.Context, pc ProbeContext) ProbeOutput {
	s := pc.Secret

	// Try to find a PEM block.
	block, _ := pem.Decode([]byte(s))
	if block == nil {
		// Try to extract from the match string (might have surrounding context).
		if idx := strings.Index(s, "-----BEGIN"); idx >= 0 {
			block, _ = pem.Decode([]byte(s[idx:]))
		}
	}

	if block == nil {
		return ProbeOutput{Status: StatusUnknown, Reason: "no PEM block found"}
	}

	meta := map[string]any{
		"type": block.Type,
	}

	// Try to parse the key to check validity.
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
		return ProbeOutput{Status: StatusUnknown, Reason: "unrecognized key type: " + block.Type, Metadata: meta}
	}
}

func probeKubernetesSecret(ctx context.Context, pc ProbeContext) ProbeOutput {
	// If the extracted value looks like a JWT, delegate to JWT probe.
	if looksLikeJWT(pc.Secret) {
		return probeJWT(ctx, pc)
	}

	// K8s secret YAML — gitleaks flags the manifest structure, not a
	// specific credential. The base64 value inside is usually a placeholder
	// or references a sealed/external secret. Mark as unknown for manual review.
	return ProbeOutput{
		Status: StatusUnknown,
		Reason: "Kubernetes Secret manifest — review if values are real credentials",
	}
}
