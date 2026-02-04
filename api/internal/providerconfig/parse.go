package providerconfig

import (
	"errors"
	"net/url"
	"strings"
)

const (
	ProviderGitHub  = "github"
	ProviderGitLab  = "gitlab"
	ProviderGitea   = "gitea"
	ProviderForgejo = "forgejo"
)

func detectTypeFromHost(host string) string {
	switch {
	case host == "github.com":
		return ProviderGitHub
	case strings.Contains(host, "gitlab"):
		return ProviderGitLab
	case strings.Contains(host, "forgejo"):
		return ProviderForgejo
	case strings.Contains(host, "gitea"):
		return ProviderGitea
	default:
		return ""
	}
}

func ensureScheme(input string) string {
	trimmed := strings.TrimSpace(input)
	if trimmed == "" {
		return trimmed
	}
	if strings.Contains(trimmed, "://") {
		return trimmed
	}
	return "https://" + trimmed
}

// ParseProviderURL parses and validates a provider URL.
func ParseProviderURL(raw string, forcedType string) (providerType, baseURL, ownerPath string, err error) {
	if strings.TrimSpace(raw) == "" {
		return "", "", "", errors.New("provider URL is required")
	}

	parsed, err := url.Parse(ensureScheme(raw))
	if err != nil {
		return "", "", "", errors.New("provider URL must be a valid URL (https://...)")
	}
	if parsed.Scheme != "https" {
		return "", "", "", errors.New("provider URL must start with https://")
	}

	host := strings.ToLower(parsed.Host)
	ownerPath = strings.Trim(parsed.Path, "/")

	if forcedType != "" {
		providerType = forcedType
	} else {
		providerType = detectTypeFromHost(host)
	}

	if providerType == "" {
		return "", "", "", errors.New("could not detect provider type")
	}

	baseURL = parsed.Scheme + "://" + parsed.Host

	if providerType == ProviderGitHub {
		parts := strings.Split(strings.Trim(ownerPath, "/"), "/")
		sanitized := make([]string, 0, len(parts))
		for _, p := range parts {
			if p != "" {
				sanitized = append(sanitized, p)
			}
		}
		if len(sanitized) == 0 {
			return "", "", "", errors.New("GitHub providers must include an org or user path")
		}
		if len(sanitized) > 1 {
			return "", "", "", errors.New("GitHub providers must point to an org or user, not a repo")
		}
		ownerPath = sanitized[0]
	}

	return providerType, baseURL, ownerPath, nil
}

// NormalizeBaseURL applies defaults when baseURL is empty.
func NormalizeBaseURL(providerType, baseURL string) string {
	if baseURL != "" {
		return strings.TrimRight(baseURL, "/")
	}
	switch providerType {
	case ProviderGitHub:
		return "https://github.com"
	case ProviderGitLab:
		return "https://gitlab.com"
	default:
		return ""
	}
}
