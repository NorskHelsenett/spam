package auth

import (
	"context"
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// graphPhotoEndpoint is the Microsoft Graph endpoint that returns the binary
// photo for the signed-in user. We request the 96x96 size — the same one
// prism uses — to keep the base64 payload small enough to embed in JSON.
const graphPhotoEndpoint = "https://graph.microsoft.com/v1.0/me/photos/96x96/$value"

var graphHTTPClient = &http.Client{Timeout: 10 * time.Second}

// fetchAzurePhotoDataURL retrieves the user's photo from Microsoft Graph using
// the OIDC access token and returns a self-contained data URL. Returns an
// empty string with no error when the user has no photo set (HTTP 404), so
// callers can cleanly fall back to Gravatar.
func fetchAzurePhotoDataURL(ctx context.Context, accessToken string) (string, error) {
	if accessToken == "" {
		return "", nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, graphPhotoEndpoint, nil)
	if err != nil {
		return "", fmt.Errorf("graph photo request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := graphHTTPClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("graph photo: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		data, err := io.ReadAll(resp.Body)
		if err != nil {
			return "", fmt.Errorf("graph photo body: %w", err)
		}
		contentType := resp.Header.Get("Content-Type")
		if contentType == "" {
			contentType = "image/jpeg"
		}
		return "data:" + contentType + ";base64," + base64.StdEncoding.EncodeToString(data), nil
	case http.StatusNotFound:
		// No photo on the account — let Gravatar take over.
		return "", nil
	default:
		return "", fmt.Errorf("graph photo: unexpected status %d", resp.StatusCode)
	}
}

// gravatarURL returns the Gravatar identicon URL for an email. d=identicon
// gives a deterministic-but-distinctive default when the email isn't on
// Gravatar; s=192 covers the 96px avatar at retina.
func gravatarURL(email string) string {
	normalized := strings.ToLower(strings.TrimSpace(email))
	if normalized == "" {
		return ""
	}
	sum := md5.Sum([]byte(normalized))
	hash := hex.EncodeToString(sum[:])
	q := url.Values{}
	q.Set("s", "192")
	q.Set("d", "identicon")
	return "https://www.gravatar.com/avatar/" + hash + "?" + q.Encode()
}

// pictureOrGravatar returns the stored picture if present, else a Gravatar URL
// derived from the email. Returns an empty string only if both inputs are empty.
func pictureOrGravatar(picture, email string) string {
	if picture != "" {
		return picture
	}
	return gravatarURL(email)
}
