package secretprobe

import (
	"context"
	"strings"
)

func init() {
	patDesc := func(pc ProbeContext) []RequestPreview {
		base := gitlabAPIBase(pc.ProviderBaseURL)
		if base == "" {
			return nil
		}
		return []RequestPreview{{
			Method:  "GET",
			URL:     base + "/user",
			Headers: map[string]string{"PRIVATE-TOKEN": "[REDACTED]"},
		}}
	}
	RegisterNetwork("gitlab-pat", probeGitLabPAT, patDesc)
	RegisterNetwork("gitlab-ptt", probeGitLabPAT, patDesc)
	RegisterNetwork("gitlab-deploy-token", probeGitLabPAT, patDesc)

	runnerDesc := func(pc ProbeContext) []RequestPreview {
		base := gitlabAPIBase(pc.ProviderBaseURL)
		if base == "" {
			return nil
		}
		return []RequestPreview{{
			Method:  "POST",
			URL:     base + "/runners/verify",
			Headers: map[string]string{"Content-Type": "application/json"},
			Body:    `{"token":"[REDACTED]"}`,
		}}
	}
	RegisterNetwork("gitlab-runner-registration-token", probeGitLabRunner, runnerDesc)
	RegisterNetwork("gitlab-runner-authentication-token", probeGitLabRunner, runnerDesc)
}

// gitlabAPIBase derives the GitLab API v4 base URL from the provider base URL.
func gitlabAPIBase(providerBaseURL string) string {
	base := strings.TrimRight(strings.TrimSpace(providerBaseURL), "/")
	if base == "" {
		return ""
	}
	return base + "/api/v4"
}

func probeGitLabPAT(ctx context.Context, pc ProbeContext) ProbeOutput {
	base := gitlabAPIBase(pc.ProviderBaseURL)
	if base == "" {
		return ProbeOutput{Status: StatusUnknown, Reason: "no provider base URL configured"}
	}

	r, err := HTTPGet(ctx, base+"/user", map[string]string{
		"PRIVATE-TOKEN": pc.Secret,
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
		return ProbeOutput{Status: StatusRevoked, Reason: "forbidden"}
	default:
		return Unknown(r)
	}
}

func probeGitLabRunner(ctx context.Context, pc ProbeContext) ProbeOutput {
	base := gitlabAPIBase(pc.ProviderBaseURL)
	if base == "" {
		return ProbeOutput{Status: StatusUnknown, Reason: "no provider base URL configured"}
	}

	r, err := HTTPPost(ctx, base+"/runners/verify", map[string]string{
		"Content-Type": "application/json",
	}, `{"token":"`+pc.Secret+`"}`)
	if err != nil {
		return ProbeOutput{Status: StatusError, Reason: err.Error()}
	}

	switch r.Status {
	case 200:
		return ProbeOutput{Status: StatusValid}
	case 403:
		return ProbeOutput{Status: StatusRevoked}
	default:
		return Unknown(r)
	}
}
