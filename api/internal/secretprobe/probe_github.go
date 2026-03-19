package secretprobe

import (
	"context"
	"strings"
)

func init() {
	patDesc := func(pc ProbeContext) []RequestPreview {
		base := githubAPIBase(pc.ProviderBaseURL)
		if base == "" {
			return nil
		}
		return []RequestPreview{{
			Method:  "GET",
			URL:     base + "/user",
			Headers: map[string]string{"Authorization": "token [REDACTED]"},
		}}
	}
	RegisterNetwork("github-pat", probeGitHubPAT, patDesc)
	RegisterNetwork("github-fine-grained-pat", probeGitHubPAT, patDesc)

	appDesc := func(pc ProbeContext) []RequestPreview {
		base := githubAPIBase(pc.ProviderBaseURL)
		if base == "" {
			return nil
		}
		return []RequestPreview{{
			Method:  "GET",
			URL:     base + "/installation/repositories?per_page=1",
			Headers: map[string]string{"Authorization": "Bearer [REDACTED]"},
		}}
	}
	RegisterNetwork("github-app-token", probeGitHubAppToken, appDesc)
}

// githubAPIBase derives the GitHub API base URL from the provider base URL.
// For github.com it returns "https://api.github.com".
// For GitHub Enterprise it appends /api/v3.
func githubAPIBase(providerBaseURL string) string {
	base := strings.TrimRight(strings.TrimSpace(providerBaseURL), "/")
	if base == "" {
		return ""
	}
	if strings.EqualFold(base, "https://github.com") {
		return "https://api.github.com"
	}
	return base + "/api/v3"
}

func probeGitHubPAT(ctx context.Context, pc ProbeContext) ProbeOutput {
	base := githubAPIBase(pc.ProviderBaseURL)
	if base == "" {
		return ProbeOutput{Status: StatusUnknown, Reason: "no provider base URL configured"}
	}

	r, err := HTTPGet(ctx, base+"/user", map[string]string{
		"Authorization": "token " + pc.Secret,
		"User-Agent":    "spam-secret-probe",
	})
	if err != nil {
		return ProbeOutput{Status: StatusError, Reason: err.Error()}
	}

	switch r.Status {
	case 200:
		meta := map[string]any{}
		if scopes := r.Header.Get("X-Oauth-Scopes"); scopes != "" {
			meta["scopes"] = scopes
		}
		return ProbeOutput{Status: StatusValid, Metadata: meta}
	case 401:
		return ProbeOutput{Status: StatusRevoked}
	case 403:
		if rateLimited := r.Header.Get("X-RateLimit-Remaining"); rateLimited == "0" {
			return ProbeOutput{Status: StatusUnknown, Reason: "rate limited"}
		}
		return ProbeOutput{Status: StatusRevoked, Reason: "forbidden"}
	default:
		return Unknown(r)
	}
}

func probeGitHubAppToken(ctx context.Context, pc ProbeContext) ProbeOutput {
	base := githubAPIBase(pc.ProviderBaseURL)
	if base == "" {
		return ProbeOutput{Status: StatusUnknown, Reason: "no provider base URL configured"}
	}

	r, err := HTTPGet(ctx, base+"/installation/repositories?per_page=1", map[string]string{
		"Authorization": "Bearer " + pc.Secret,
		"User-Agent":    "spam-secret-probe",
	})
	if err != nil {
		return ProbeOutput{Status: StatusError, Reason: err.Error()}
	}

	switch r.Status {
	case 200:
		return ProbeOutput{Status: StatusValid}
	case 401:
		return ProbeOutput{Status: StatusRevoked}
	case 403:
		if rateLimited := r.Header.Get("X-RateLimit-Remaining"); rateLimited == "0" {
			return ProbeOutput{Status: StatusUnknown, Reason: "rate limited"}
		}
		return ProbeOutput{Status: StatusRevoked, Reason: "forbidden"}
	default:
		return Unknown(r)
	}
}
