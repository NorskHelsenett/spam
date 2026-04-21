package secretprobe

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

func init() {
	Register("jwt", &jwtProber{})
	Register("jwt-base64", &jwtProber{})
}

// jwtProber is a network prober that first does offline JWT analysis (claims,
// expiry) and then optionally verifies the token signature against the
// issuer's JWKS endpoint (discovered via OpenID Connect).
type jwtProber struct{}

func (j *jwtProber) Kind() ProbeKind { return ProbeKindNetwork }

func (j *jwtProber) Describe(pc ProbeContext) []RequestPreview {
	iss := jwtIssuer(pc.Secret)
	if iss == "" {
		return nil
	}
	discoveryURL := strings.TrimRight(iss, "/") + "/.well-known/openid-configuration"
	return []RequestPreview{
		{Method: "GET", URL: discoveryURL},
		{Method: "GET", URL: discoveryURL + " → jwks_uri"},
	}
}

func (j *jwtProber) Probe(ctx context.Context, pc ProbeContext) ProbeOutput {
	// Phase 1: offline claims analysis (always runs).
	out := probeJWT(ctx, pc)

	// Phase 2: if we got a usable issuer, verify the signature via JWKS.
	iss := jwtIssuer(pc.Secret)
	if iss == "" {
		return out
	}

	kid := jwtKID(pc.Secret)
	sigResult := verifyJWTSignature(ctx, pc.Secret, iss, kid)

	// Merge signature verification into metadata.
	if out.Metadata == nil {
		out.Metadata = map[string]any{}
	}
	out.Metadata["signature_status"] = string(sigResult.Status)
	if sigResult.Reason != "" {
		out.Metadata["signature_reason"] = sigResult.Reason
	}

	// If the token is expired but signature is valid, keep expired status.
	// If signature verification says invalid/revoked, prefer that.
	if sigResult.Status == StatusInvalid {
		out.Status = StatusInvalid
		out.Reason = "signature verification failed"
	}

	return out
}

// probeJWT is the offline-only JWT analysis (claims + expiry). Exported for
// use by classify.go and probe_generic.go.
func probeJWT(_ context.Context, pc ProbeContext) ProbeOutput {
	parts := strings.SplitN(pc.Secret, ".", 3)
	if len(parts) < 2 {
		return ProbeOutput{Status: StatusError, Reason: "not a valid JWT (missing parts)"}
	}

	payload, err := base64Decode(parts[1])
	if err != nil {
		return ProbeOutput{Status: StatusError, Reason: "failed to decode payload: " + err.Error()}
	}

	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return ProbeOutput{Status: StatusError, Reason: "invalid JSON payload"}
	}

	meta := map[string]any{}
	if iss, ok := claims["iss"].(string); ok {
		meta["issuer"] = iss
	}
	if sub, ok := claims["sub"].(string); ok {
		meta["subject"] = sub
	}

	exp, hasExp := numericClaim(claims, "exp")
	if !hasExp {
		return ProbeOutput{Status: StatusUnknown, Reason: "no expiry claim", Metadata: meta}
	}

	expTime := time.Unix(int64(exp), 0)
	meta["expires_at"] = expTime.UTC().Format(time.RFC3339)

	if expTime.Before(time.Now()) {
		meta["expired_ago"] = fmt.Sprintf("%s", time.Since(expTime).Round(time.Minute))
		return ProbeOutput{Status: StatusExpired, Reason: "expired", Metadata: meta}
	}

	meta["expires_in"] = fmt.Sprintf("%s", time.Until(expTime).Round(time.Minute))
	return ProbeOutput{Status: StatusValid, Metadata: meta}
}

// verifyJWTSignature fetches the issuer's OIDC discovery document, retrieves
// the JWKS, and verifies the JWT signature against the matching key.
func verifyJWTSignature(ctx context.Context, token, issuer, kid string) ProbeOutput {
	discoveryURL := strings.TrimRight(issuer, "/") + "/.well-known/openid-configuration"

	// Fetch OpenID Connect discovery document.
	resp, err := HTTPGet(ctx, discoveryURL, nil)
	if err != nil {
		return ProbeOutput{Status: StatusUnknown, Reason: "failed to fetch OIDC discovery: " + err.Error()}
	}
	if resp.Status != 200 {
		return ProbeOutput{Status: StatusUnknown, Reason: fmt.Sprintf("OIDC discovery returned %d", resp.Status)}
	}

	var discovery struct {
		JWKsURI string `json:"jwks_uri"`
		Issuer  string `json:"issuer"`
	}
	if err := json.Unmarshal([]byte(resp.Body), &discovery); err != nil {
		return ProbeOutput{Status: StatusUnknown, Reason: "invalid OIDC discovery JSON"}
	}
	if discovery.JWKsURI == "" {
		return ProbeOutput{Status: StatusUnknown, Reason: "OIDC discovery has no jwks_uri"}
	}

	// Verify the issuer in the discovery document matches what the token claims.
	if discovery.Issuer != "" && discovery.Issuer != issuer {
		return ProbeOutput{
			Status: StatusInvalid,
			Reason: fmt.Sprintf("issuer mismatch: token has %q but discovery has %q", issuer, discovery.Issuer),
			Metadata: map[string]any{
				"token_issuer":     issuer,
				"discovery_issuer": discovery.Issuer,
			},
		}
	}

	// Fetch JWKS.
	jwksResp, err := HTTPGet(ctx, discovery.JWKsURI, nil)
	if err != nil {
		return ProbeOutput{Status: StatusUnknown, Reason: "failed to fetch JWKS: " + err.Error()}
	}
	if jwksResp.Status != 200 {
		return ProbeOutput{Status: StatusUnknown, Reason: fmt.Sprintf("JWKS endpoint returned %d", jwksResp.Status)}
	}

	var jwks struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal([]byte(jwksResp.Body), &jwks); err != nil {
		return ProbeOutput{Status: StatusUnknown, Reason: "invalid JWKS JSON"}
	}

	if len(jwks.Keys) == 0 {
		return ProbeOutput{Status: StatusUnknown, Reason: "JWKS has no keys"}
	}

	// Find matching key by kid.
	meta := map[string]any{
		"jwks_uri":   discovery.JWKsURI,
		"jwks_keys":  len(jwks.Keys),
		"token_kid":  kid,
	}

	if kid == "" {
		// No kid in the JWT header — we can't match a specific key.
		return ProbeOutput{
			Status:   StatusUnknown,
			Reason:   "no kid in JWT header, cannot match JWKS key",
			Metadata: meta,
		}
	}

	found := false
	for _, rawKey := range jwks.Keys {
		var keyInfo struct {
			KID string `json:"kid"`
			Alg string `json:"alg"`
			Kty string `json:"kty"`
			Use string `json:"use"`
		}
		if err := json.Unmarshal(rawKey, &keyInfo); err != nil {
			continue
		}
		if keyInfo.KID == kid {
			found = true
			meta["matched_key_alg"] = keyInfo.Alg
			meta["matched_key_kty"] = keyInfo.Kty
			if keyInfo.Use != "" {
				meta["matched_key_use"] = keyInfo.Use
			}
			break
		}
	}
	if !found {
		return ProbeOutput{
			Status:   StatusInvalid,
			Reason:   fmt.Sprintf("kid %q not found in JWKS (%d keys)", kid, len(jwks.Keys)),
			Metadata: meta,
		}
	}

	// We found the matching key in the issuer's JWKS. Full cryptographic
	// signature verification is not performed — report as unknown rather
	// than valid to avoid false confidence.
	return ProbeOutput{
		Status:   StatusUnknown,
		Reason:   "kid found in issuer JWKS (signature not cryptographically verified)",
		Metadata: meta,
	}
}

// jwtIssuer extracts the "iss" claim from a JWT without verifying it.
func jwtIssuer(token string) string {
	parts := strings.SplitN(token, ".", 3)
	if len(parts) < 2 {
		return ""
	}
	payload, err := base64Decode(parts[1])
	if err != nil {
		return ""
	}
	var claims struct {
		Iss string `json:"iss"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return ""
	}
	// Only return HTTPS issuers — we need a secure URL to fetch discovery from.
	// Allowing http:// would enable SSRF against internal/metadata endpoints.
	if strings.HasPrefix(claims.Iss, "https://") {
		return claims.Iss
	}
	return ""
}

// jwtKID extracts the "kid" (key ID) from a JWT header without verifying it.
func jwtKID(token string) string {
	parts := strings.SplitN(token, ".", 3)
	if len(parts) < 2 {
		return ""
	}
	header, err := base64Decode(parts[0])
	if err != nil {
		return ""
	}
	var h struct {
		KID string `json:"kid"`
	}
	if err := json.Unmarshal(header, &h); err != nil {
		return ""
	}
	return h.KID
}

func numericClaim(claims map[string]any, key string) (float64, bool) {
	v, ok := claims[key]
	if !ok {
		return 0, false
	}
	switch n := v.(type) {
	case float64:
		return n, true
	case json.Number:
		f, err := n.Float64()
		return f, err == nil
	default:
		return 0, false
	}
}

func base64Decode(s string) ([]byte, error) {
	// JWT uses URL-safe base64 without padding
	s = strings.ReplaceAll(s, "-", "+")
	s = strings.ReplaceAll(s, "_", "/")
	switch len(s) % 4 {
	case 2:
		s += "=="
	case 3:
		s += "="
	}
	return base64.StdEncoding.DecodeString(s)
}
