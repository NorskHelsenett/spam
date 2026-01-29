package runner

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

var (
	ErrInvalidToken = errors.New("invalid token")
	ErrTokenExpired = errors.New("token expired")
)

// TokenClaims contains the claims for a run token.
type TokenClaims struct {
	RunID     string    `json:"run_id"`
	IssuedAt  time.Time `json:"iat"`
	ExpiresAt time.Time `json:"exp"`
}

// GenerateRunToken creates a signed token for a run.
func GenerateRunToken(hmacKey []byte, runID string, ttl time.Duration) (string, error) {
	now := time.Now()
	claims := TokenClaims{
		RunID:     runID,
		IssuedAt:  now,
		ExpiresAt: now.Add(ttl),
	}

	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("marshal claims: %w", err)
	}

	// Base64 encode the claims
	payload := base64.RawURLEncoding.EncodeToString(claimsJSON)

	// Create HMAC signature
	sig := computeHMAC(hmacKey, payload)
	sigB64 := base64.RawURLEncoding.EncodeToString(sig)

	// Token format: payload.signature
	return payload + "." + sigB64, nil
}

// ValidateRunToken validates a run token and returns the claims.
func ValidateRunToken(hmacKey []byte, token string) (*TokenClaims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return nil, ErrInvalidToken
	}

	payload := parts[0]
	sigB64 := parts[1]

	// Verify signature
	expectedSig := computeHMAC(hmacKey, payload)
	actualSig, err := base64.RawURLEncoding.DecodeString(sigB64)
	if err != nil {
		return nil, ErrInvalidToken
	}

	if !hmac.Equal(expectedSig, actualSig) {
		return nil, ErrInvalidToken
	}

	// Decode claims
	claimsJSON, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return nil, ErrInvalidToken
	}

	var claims TokenClaims
	if err := json.Unmarshal(claimsJSON, &claims); err != nil {
		return nil, ErrInvalidToken
	}

	// Check expiration
	if time.Now().After(claims.ExpiresAt) {
		return nil, ErrTokenExpired
	}

	return &claims, nil
}

func computeHMAC(key []byte, message string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(message))
	return h.Sum(nil)
}
