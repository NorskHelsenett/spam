package secretprobe

import "context"

func init() {
	desc := func(pc ProbeContext) []RequestPreview {
		return []RequestPreview{{
			Method:  "GET",
			URL:     "https://api.github.com/user",
			Headers: map[string]string{"Authorization": "token [REDACTED]"},
		}}
	}
	RegisterNetwork("github-pat", probeGitHubPAT, desc)
	RegisterNetwork("github-fine-grained-pat", probeGitHubPAT, desc)
}

func probeGitHubPAT(ctx context.Context, pc ProbeContext) ProbeOutput {
	r, err := HTTPGet(ctx, "https://api.github.com/user", map[string]string{
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
