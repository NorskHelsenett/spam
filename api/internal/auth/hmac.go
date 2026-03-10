package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
)

// HMACMiddleware returns middleware that verifies the X-Scanner-Signature
// header (hex-encoded HMAC-SHA256 of the raw request body) using hmacKey.
// Returns 401 if the signature is missing or invalid.
// If hmacKey is empty the middleware is a no-op (passes all requests).
func HMACMiddleware(hmacKey string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if hmacKey == "" {
				next.ServeHTTP(w, r)
				return
			}

			sig := r.Header.Get("X-Scanner-Signature")
			if sig == "" {
				http.Error(w, "missing X-Scanner-Signature", http.StatusUnauthorized)
				return
			}

			body, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, "failed to read body", http.StatusBadRequest)
				return
			}
			defer r.Body.Close()

			// Replace body so downstream handlers can still read it.
			r.Body = io.NopCloser(io.Reader(newBytesReader(body)))

			mac := hmac.New(sha256.New, []byte(hmacKey))
			mac.Write(body)
			expected := hex.EncodeToString(mac.Sum(nil))

			if !hmac.Equal([]byte(sig), []byte(expected)) {
				http.Error(w, "invalid signature", http.StatusUnauthorized)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// newBytesReader wraps a byte slice in an io.Reader.
type bytesReader struct {
	data []byte
	pos  int
}

func newBytesReader(b []byte) *bytesReader { return &bytesReader{data: b} }

func (r *bytesReader) Read(p []byte) (n int, err error) {
	if r.pos >= len(r.data) {
		return 0, io.EOF
	}
	n = copy(p, r.data[r.pos:])
	r.pos += n
	return n, nil
}
