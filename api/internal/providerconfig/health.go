package providerconfig

import (
	"context"
	"fmt"
	"strings"

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
	client := NewProviderClient(providerType, baseURL, token)
	if client == nil {
		return "unsupported provider type", fmt.Errorf("unsupported provider type %q", providerType)
	}

	_, _, err := client.ListPublicRepos(ctx, ownerPath, providers.ListOptions{
		Page:     1,
		PageSize: 1,
	})
	if err != nil {
		return "provider health check failed", err
	}

	return "", nil
}
