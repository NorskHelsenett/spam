// Package secrets holds the AES-GCM helpers used to protect stored
// credentials (git provider PATs, LLM API keys). Deliberately a leaf
// package — it must stay importable from anywhere without dragging in
// model packages, so it can never participate in an import cycle.
package secrets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"strings"
)

// ParseSecretKey parses a raw or base64 key string.
func ParseSecretKey(raw string) ([]byte, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil, nil
	}
	if isValidAESKey([]byte(trimmed)) {
		return []byte(trimmed), nil
	}
	decoded, err := base64.StdEncoding.DecodeString(trimmed)
	if err == nil && isValidAESKey(decoded) {
		return decoded, nil
	}
	return nil, errors.New("provider secrets key must be 16, 24, or 32 bytes (raw or base64)")
}

// IsValidKey reports whether key is a usable AES key length.
func IsValidKey(key []byte) bool { return isValidAESKey(key) }

func isValidAESKey(key []byte) bool {
	switch len(key) {
	case 16, 24, 32:
		return true
	default:
		return false
	}
}

// EncryptToken encrypts the given token with AES-GCM.
func EncryptToken(key []byte, token string) ([]byte, error) {
	if !isValidAESKey(key) {
		return nil, errors.New("provider secrets key not configured")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	ciphertext := gcm.Seal(nil, nonce, []byte(token), nil)
	return append(nonce, ciphertext...), nil
}

// DecryptToken decrypts the given encrypted token blob.
func DecryptToken(key []byte, blob []byte) (string, error) {
	if !isValidAESKey(key) {
		return "", errors.New("provider secrets key not configured")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonceSize := gcm.NonceSize()
	if len(blob) < nonceSize {
		return "", errors.New("invalid token blob")
	}
	nonce := blob[:nonceSize]
	ciphertext := blob[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

// FingerprintToken returns a masked fingerprint for display.
func FingerprintToken(token string) string {
	trimmed := strings.TrimSpace(token)
	if trimmed == "" {
		return ""
	}
	if len(trimmed) <= 4 {
		return "****" + trimmed
	}
	return "****" + trimmed[len(trimmed)-4:]
}
