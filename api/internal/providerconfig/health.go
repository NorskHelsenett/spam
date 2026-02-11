package providerconfig

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/NorskHelsenett/spam/internal/providers"
)

func githubAPIBaseURL(baseURL string) string {
	trimmed := strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if trimmed == "" || strings.EqualFold(trimmed, "https://github.com") {
		return ""
	}
	return trimmed + "/api/v3"
}

// NewProviderClient creates an API client for the configured provider.
func NewProviderClient(providerType, baseURL, token string) providers.Client {
	switch providerType {
	case ProviderGitHub:
		return providers.NewGitHubClient(githubAPIBaseURL(baseURL), token)
	case ProviderGitLab:
		return providers.NewGitLabClient(baseURL, token)
	case ProviderGitea, ProviderForgejo:
		return providers.NewGiteaClient(baseURL, token)
	default:
		return nil
	}
}

// CheckProviderHealth verifies the provider can be reached and queried.
func CheckProviderHealth(ctx context.Context, providerType, baseURL, ownerPath, token string) (string, error) {
	url, authHeader, err := providerHealthProbe(providerType, baseURL, token)
	if err != nil {
		return "unsupported provider type", err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "provider health request failed", err
	}
	req.Header.Set("Accept", "application/json")
	if authHeader != "" {
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) == 2 {
			req.Header.Set(parts[0], parts[1])
		}
	}

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "provider API unreachable", err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return "", nil
	}

	msg := fmt.Sprintf("provider API returned %d", resp.StatusCode)
	if resp.StatusCode == http.StatusTooManyRequests {
		msg = "provider API returned 429 (rate limited)"
	}
	if resp.StatusCode == http.StatusBadGateway {
		msg = "provider API returned 502 (bad gateway)"
	}
	if retryAfter := strings.TrimSpace(resp.Header.Get("Retry-After")); retryAfter != "" {
		msg = fmt.Sprintf("%s; retry-after=%s", msg, retryAfter)
	}
	if reset := strings.TrimSpace(resp.Header.Get("X-RateLimit-Reset")); reset != "" {
		if unix, parseErr := strconv.ParseInt(reset, 10, 64); parseErr == nil && unix > 0 {
			msg = fmt.Sprintf("%s; rate-limit-reset=%s", msg, time.Unix(unix, 0).UTC().Format(time.RFC3339))
		} else {
			msg = fmt.Sprintf("%s; rate-limit-reset=%s", msg, reset)
		}
	}
	if remaining := strings.TrimSpace(resp.Header.Get("X-RateLimit-Remaining")); remaining != "" {
		msg = fmt.Sprintf("%s; remaining=%s", msg, remaining)
	}

	return msg, fmt.Errorf("health probe status %d", resp.StatusCode)
}

func providerHealthProbe(providerType, baseURL, token string) (url, authHeader string, err error) {
	switch providerType {
	case ProviderGitHub:
		apiBase := githubAPIBaseURL(baseURL)
		if apiBase == "" {
			apiBase = "https://api.github.com"
		}
		if strings.TrimSpace(token) != "" {
			return apiBase + "/user", "Authorization Bearer " + strings.TrimSpace(token), nil
		}
		return apiBase + "/rate_limit", "", nil
	case ProviderGitLab:
		apiBase := strings.TrimRight(strings.TrimSpace(baseURL), "/")
		if apiBase == "" {
			apiBase = "https://gitlab.com"
		}
		if !strings.HasSuffix(apiBase, "/api/v4") {
			apiBase += "/api/v4"
		}
		if strings.TrimSpace(token) != "" {
			return apiBase + "/user", "PRIVATE-TOKEN " + strings.TrimSpace(token), nil
		}
		return apiBase + "/projects?per_page=1&page=1", "", nil
	case ProviderGitea, ProviderForgejo:
		apiBase := strings.TrimRight(strings.TrimSpace(baseURL), "/")
		if apiBase == "" {
			return "", "", fmt.Errorf("base URL is required for %s", providerType)
		}
		if !strings.HasSuffix(apiBase, "/api/v1") {
			apiBase += "/api/v1"
		}
		if strings.TrimSpace(token) != "" {
			return apiBase + "/user", "Authorization token " + strings.TrimSpace(token), nil
		}
		return apiBase + "/repos/search?limit=1&page=1", "", nil
	default:
		return "", "", fmt.Errorf("unsupported provider type %q", providerType)
	}
}
