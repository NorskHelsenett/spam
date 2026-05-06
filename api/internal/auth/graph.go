package auth

import (
	"context"
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// graphPhotoEndpoint is the Microsoft Graph endpoint that returns the binary
// photo for the signed-in user. We request the 96x96 size — the same one
// prism uses — to keep the base64 payload small enough to embed in JSON.
const graphPhotoEndpoint = "https://graph.microsoft.com/v1.0/me/photos/96x96/$value"

// graphMemberOfEndpoint returns the directory objects (groups + directory
// roles) the signed-in user is a direct member of. We request a generous
// page size and ask only for displayName to keep the payload small.
const graphMemberOfEndpoint = "https://graph.microsoft.com/v1.0/me/memberOf?$select=displayName,id&$top=200"

// graphMaxGroupPages caps pagination so a user with thousands of groups
// can't stall login. 5 pages * 200 = 1000 group names is plenty for the UI.
const graphMaxGroupPages = 5

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

// fetchAzureGroupNames retrieves the display names of EntraID groups the user
// is a direct member of via Microsoft Graph /me/memberOf. The result is sorted
// for stable rendering and de-duplicated. Returns nil with no error when the
// access token lacks Graph access (403/401) so callers can treat it as
// "groups unavailable" rather than a hard failure.
func fetchAzureGroupNames(ctx context.Context, accessToken string) ([]string, error) {
	if accessToken == "" {
		return nil, nil
	}

	type graphDirObj struct {
		ODataType   string `json:"@odata.type"`
		DisplayName string `json:"displayName"`
		ID          string `json:"id"`
	}
	type graphPage struct {
		Value    []graphDirObj `json:"value"`
		NextLink string        `json:"@odata.nextLink"`
	}

	seen := make(map[string]struct{})
	var names []string

	next := graphMemberOfEndpoint
	for page := 0; page < graphMaxGroupPages && next != ""; page++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, next, nil)
		if err != nil {
			return nil, fmt.Errorf("graph memberOf request: %w", err)
		}
		req.Header.Set("Authorization", "Bearer "+accessToken)
		req.Header.Set("Accept", "application/json")

		resp, err := graphHTTPClient.Do(req)
		if err != nil {
			return nil, fmt.Errorf("graph memberOf: %w", err)
		}

		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			resp.Body.Close()
			// Token lacks GroupMember.Read.All / Directory.Read.All — soft fail.
			return nil, nil
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			return nil, fmt.Errorf("graph memberOf: unexpected status %d", resp.StatusCode)
		}

		var body graphPage
		if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
			resp.Body.Close()
			return nil, fmt.Errorf("graph memberOf decode: %w", err)
		}
		resp.Body.Close()

		for _, obj := range body.Value {
			// Filter to actual groups; memberOf also returns directoryRole
			// entries which would clutter the user-facing list.
			if !strings.HasSuffix(obj.ODataType, "graph.group") {
				continue
			}
			name := strings.TrimSpace(obj.DisplayName)
			if name == "" {
				continue
			}
			if _, dup := seen[name]; dup {
				continue
			}
			seen[name] = struct{}{}
			names = append(names, name)
		}

		next = body.NextLink
	}

	sort.Strings(names)
	return names, nil
}
