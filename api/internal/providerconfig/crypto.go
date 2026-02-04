package providerconfig

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"strings"
)

const (
	minSecretKeyLen = 32
)

// ParseSecretKey parses a raw or base64 key string.
func ParseSecretKey(raw string) ([]byte, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil, nil
	}
	decoded, err := base64.StdEncoding.DecodeString(trimmed)
	if err == nil {
		if len(decoded) < minSecretKeyLen {
			return nil, errors.New("provider secrets key must be at least 32 bytes")
		}
		return decoded, nil
	}
	if len(trimmed) < minSecretKeyLen {
		return nil, errors.New("provider secrets key must be at least 32 bytes")
	}
	return []byte(trimmed), nil
}

// EncryptToken encrypts the given token with AES-GCM.
func EncryptToken(key []byte, token string) ([]byte, error) {
	if len(key) < minSecretKeyLen {
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
	if len(key) < minSecretKeyLen {
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
