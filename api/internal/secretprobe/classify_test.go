package secretprobe

import (
	"encoding/base64"
	"testing"
)

func TestClassify_JWTInCurlAuthHeader(t *testing.T) {
	// A curl-auth-header that is actually a JWT should be reclassified.
	jwt := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ0ZXN0Iiwic3ViIjoiMTIzIiwiZXhwIjoxNjI1NzQwNjY1fQ.signature"
	c := Classify(jwt, "curl-auth-header")
	if !c.Reclassified {
		t.Error("expected curl-auth-header containing JWT to be reclassified")
	}
	if c.EffectiveRuleID != "jwt" {
		t.Errorf("expected effective rule 'jwt', got %q", c.EffectiveRuleID)
	}
	if c.ProbeOutput.Status != StatusExpired {
		t.Errorf("expected expired JWT, got %s", c.ProbeOutput.Status)
	}
}

func TestClassify_JWTBase64NotActuallyJWT(t *testing.T) {
	// A jwt-base64 rule match that isn't a JWT at all.
	c := Classify("not-a-jwt-token-at-all", "jwt-base64")
	if c.ProbeOutput.Status != StatusInvalid {
		t.Errorf("expected invalid for non-JWT, got %s: %s", c.ProbeOutput.Status, c.ProbeOutput.Reason)
	}
}

func TestClassify_JWTBase64WithBase64EncodedJWT(t *testing.T) {
	// A base64-encoded JWT that should be decoded and recognized.
	jwt := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ0ZXN0Iiwic3ViIjoiMTIzIiwiZXhwIjoxNjI1NzQwNjY1fQ.signature"
	encoded := base64.StdEncoding.EncodeToString([]byte(jwt))
	c := Classify(encoded, "jwt-base64")
	if c.ProbeOutput.Status != StatusExpired {
		t.Errorf("expected expired JWT from base64-decoded value, got %s: %s", c.ProbeOutput.Status, c.ProbeOutput.Reason)
	}
}

func TestClassify_PrivateKeyWithCertificate(t *testing.T) {
	// A certificate misclassified as private-key.
	cert := `-----BEGIN CERTIFICATE-----
MIIBkTCB+wIJALRiMLAh2wR3MA0GCSqGSIb3DQEBCwUAMBExDzANBgNVBAMMBnRl
c3RjYTAeFw0yMzAxMDEwMDAwMDBaFw0yNDAxMDEwMDAwMDBaMBExDzANBgNVBAMM
BnRlc3RjYTBcMA0GCSqGSIb3DQEBAQUAA0sAMEgCQQC7o96h+ZhZz3+FdeYGCfJV
PKRRZEWnDMC0zAGs47LqI7EDxjjHT00SN2ITCWbaCMZk5RwPajYBsxisXNOPFVpn
AgMBAAEwDQYJKoZIhvcNAQELBQADQQBkBY+XCJhI3BHhBQq/cMUWcjL6aNVqGbjN
I7Mh3JqWI7aQy56KKc6lYaVfJMYnXbUCuN5Jh16PoXznORKqFy0I
-----END CERTIFICATE-----`
	c := Classify(cert, "private-key")
	if c.ProbeOutput.Status != StatusInvalid {
		t.Errorf("expected invalid for certificate in private-key rule, got %s: %s", c.ProbeOutput.Status, c.ProbeOutput.Reason)
	}
	if c.ProbeOutput.Reason != "certificate, not a secret" {
		t.Errorf("expected 'certificate, not a secret' reason, got %q", c.ProbeOutput.Reason)
	}
}

func TestClassify_PrivateKeyNoPEM(t *testing.T) {
	// Random string categorized as private-key but no PEM block.
	c := Classify("this-is-not-a-private-key", "private-key")
	if c.ProbeOutput.Status != StatusInvalid {
		t.Errorf("expected invalid for non-PEM in private-key rule, got %s", c.ProbeOutput.Status)
	}
}

func TestClassify_Base64EncodedPEM(t *testing.T) {
	// A base64-encoded certificate detected as private-key.
	cert := `-----BEGIN CERTIFICATE-----
MIIBkTCB+wIJALRiMLAh2wR3MA0GCSqGSIb3DQEBCwUAMBExDzANBgNVBAMMBnRl
c3RjYTAeFw0yMzAxMDEwMDAwMDBaFw0yNDAxMDEwMDAwMDBaMBExDzANBgNVBAMM
BnRlc3RjYTBcMA0GCSqGSIb3DQEBAQUAA0sAMEgCQQC7o96h+ZhZz3+FdeYGCfJV
PKRRZEWnDMC0zAGs47LqI7EDxjjHT00SN2ITCWbaCMZk5RwPajYBsxisXNOPFVpn
AgMBAAEwDQYJKoZIhvcNAQELBQADQQBkBY+XCJhI3BHhBQq/cMUWcjL6aNVqGbjN
I7Mh3JqWI7aQy56KKc6lYaVfJMYnXbUCuN5Jh16PoXznORKqFy0I
-----END CERTIFICATE-----`
	encoded := base64.StdEncoding.EncodeToString([]byte(cert))
	c := Classify(encoded, "generic-api-key")
	if c.ProbeOutput.Status != StatusInvalid {
		t.Errorf("expected invalid for base64-encoded certificate, got %s: %s", c.ProbeOutput.Status, c.ProbeOutput.Reason)
	}
	if c.ProbeOutput.Reason != "certificate, not a secret" {
		t.Errorf("expected 'certificate, not a secret' reason, got %q", c.ProbeOutput.Reason)
	}
}

func TestClassify_PublicKey(t *testing.T) {
	// Public key misclassified as private-key.
	pubkey := `-----BEGIN PUBLIC KEY-----
MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBALuj3qH5mFnPf4V15gYJ8lU8pFFkRacM
wLTMAazjsuojsQPGOMdPTRI3YhMJZtoIxmTlHA9qtgGzGKxc048VWmcCAwEAAQ==
-----END PUBLIC KEY-----`
	c := Classify(pubkey, "private-key")
	if c.ProbeOutput.Status != StatusInvalid {
		t.Errorf("expected invalid for public key, got %s: %s", c.ProbeOutput.Status, c.ProbeOutput.Reason)
	}
	if c.ProbeOutput.Reason != "public key, not a secret" {
		t.Errorf("expected 'public key, not a secret' reason, got %q", c.ProbeOutput.Reason)
	}
}

func TestClassify_RealJWT(t *testing.T) {
	// A real JWT that is classified as jwt already (no reclassification needed).
	jwt := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ0ZXN0Iiwic3ViIjoiMTIzIiwiZXhwIjoxNjI1NzQwNjY1fQ.signature"
	c := Classify(jwt, "jwt")
	if c.Reclassified {
		t.Error("jwt rule matching actual JWT should not be reclassified")
	}
	if c.EffectiveRuleID != "jwt" {
		t.Errorf("expected effective rule 'jwt', got %q", c.EffectiveRuleID)
	}
	if c.ProbeOutput.Status != StatusExpired {
		t.Errorf("expected expired, got %s", c.ProbeOutput.Status)
	}
}

func TestClassify_GenericAPIKeyThatIsJWT(t *testing.T) {
	// A generic-api-key that is actually a JWT.
	jwt := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ0ZXN0Iiwic3ViIjoiMTIzIiwiZXhwIjoxNjI1NzQwNjY1fQ.signature"
	c := Classify(jwt, "generic-api-key")
	if !c.Reclassified {
		t.Error("expected generic-api-key containing JWT to be reclassified")
	}
	if c.EffectiveRuleID != "jwt" {
		t.Errorf("expected effective rule 'jwt', got %q", c.EffectiveRuleID)
	}
}

func TestTryBase64Decode(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantLen int // 0 means empty (no decode)
	}{
		{"plain text JWT", "eyJhbGciOiJIUzI1NiJ9.payload.sig", 0},
		{"PEM block", "-----BEGIN RSA PRIVATE KEY-----\ndata\n-----END RSA PRIVATE KEY-----", 0},
		{"URL", "https://example.com/token", 0},
		{"too short", "abc", 0},
		{"valid base64", base64.StdEncoding.EncodeToString([]byte("hello world this is a test")), 25},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tryBase64Decode(tt.input)
			if tt.wantLen == 0 && result != "" {
				t.Errorf("expected empty, got %q", result)
			}
			if tt.wantLen > 0 && len(result) != tt.wantLen {
				t.Errorf("expected len %d, got %d (%q)", tt.wantLen, len(result), result)
			}
		})
	}
}

func TestClassifyPEM_Certificate(t *testing.T) {
	cert := `-----BEGIN CERTIFICATE-----
MIIBkTCB+wIJALRiMLAh2wR3MA0GCSqGSIb3DQEBCwUAMBExDzANBgNVBAMMBnRl
c3RjYTAeFw0yMzAxMDEwMDAwMDBaFw0yNDAxMDEwMDAwMDBaMBExDzANBgNVBAMM
BnRlc3RjYTBcMA0GCSqGSIb3DQEBAQUAA0sAMEgCQQC7o96h+ZhZz3+FdeYGCfJV
PKRRZEWnDMC0zAGs47LqI7EDxjjHT00SN2ITCWbaCMZk5RwPajYBsxisXNOPFVpn
AgMBAAEwDQYJKoZIhvcNAQELBQADQQBkBY+XCJhI3BHhBQq/cMUWcjL6aNVqGbjN
I7Mh3JqWI7aQy56KKc6lYaVfJMYnXbUCuN5Jh16PoXznORKqFy0I
-----END CERTIFICATE-----`
	out := classifyPEM(cert)
	if out.Status != StatusInvalid || out.Reason != "certificate, not a secret" {
		t.Errorf("got status=%s reason=%q, want invalid/'certificate, not a secret'", out.Status, out.Reason)
	}
}

func TestClassifyPEM_PublicKey(t *testing.T) {
	pub := `-----BEGIN PUBLIC KEY-----
MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBALuj3qH5mFnPf4V15gYJ8lU8pFFkRacM
wLTMAazjsuojsQPGOMdPTRI3YhMJZtoIxmTlHA9qtgGzGKxc048VWmcCAwEAAQ==
-----END PUBLIC KEY-----`
	out := classifyPEM(pub)
	if out.Status != StatusInvalid || out.Reason != "public key, not a secret" {
		t.Errorf("got status=%s reason=%q", out.Status, out.Reason)
	}
}
