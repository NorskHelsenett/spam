package providerconfig

import "github.com/NorskHelsenett/spam/internal/secrets"

// The crypto implementation lives in internal/secrets (a leaf package
// shared with llmadvisory); these wrappers keep providerconfig's
// public surface unchanged for existing callers.

// ParseSecretKey parses a raw or base64 key string.
func ParseSecretKey(raw string) ([]byte, error) { return secrets.ParseSecretKey(raw) }

// EncryptToken encrypts the given token with AES-GCM.
func EncryptToken(key []byte, token string) ([]byte, error) {
	return secrets.EncryptToken(key, token)
}

// DecryptToken decrypts the given encrypted token blob.
func DecryptToken(key []byte, blob []byte) (string, error) {
	return secrets.DecryptToken(key, blob)
}

// FingerprintToken returns a masked fingerprint for display.
func FingerprintToken(token string) string { return secrets.FingerprintToken(token) }

func isValidAESKey(key []byte) bool { return secrets.IsValidKey(key) }
