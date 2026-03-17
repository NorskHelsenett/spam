package secretprobe

import (
	"context"
	"strings"
)

func init() {
	desc := func(pc ProbeContext) []RequestPreview {
		base := strings.TrimRight(pc.ProviderBaseURL, "/")
		if base == "" {
			base = "https://gitlab.com"
		}
		return []RequestPreview{{
			Method:  "GET",
			URL:     base + "/api/v4/user",
			Headers: map[string]string{"PRIVATE-TOKEN": "[REDACTED]"},
		}}
	}
	RegisterNetwork("gitlab-pat", probeGitLabPAT, desc)
	RegisterNetwork("gitlab-ptt", probeGitLabPAT, desc)
}

func probeGitLabPAT(ctx context.Context, pc ProbeContext) ProbeOutput {
	base := strings.TrimRight(pc.ProviderBaseURL, "/")
	if base == "" {
		base = "https://gitlab.com"
	}

	r, err := HTTPGet(ctx, base+"/api/v4/user", map[string]string{
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
