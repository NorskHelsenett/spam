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
	RegisterOffline("jwt", probeJWT)
	RegisterOffline("jwt-base64", probeJWT)
}

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
