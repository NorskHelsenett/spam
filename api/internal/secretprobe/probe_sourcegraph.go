package secretprobe

import "context"

func init() {
	RegisterNetwork("sourcegraph-access-token", probeSourcegraph, func(pc ProbeContext) []RequestPreview {
		return []RequestPreview{{
			Method:  "GET",
			URL:     "https://sourcegraph.com/.api/user",
			Headers: map[string]string{"Authorization": "token [REDACTED]"},
		}}
	})
}

func probeSourcegraph(ctx context.Context, pc ProbeContext) ProbeOutput {
	r, err := HTTPGet(ctx, "https://sourcegraph.com/.api/user", map[string]string{
		"Authorization": "token " + pc.Secret,
	})
	if err != nil {
		return ProbeOutput{Status: StatusError, Reason: err.Error()}
	}

	switch r.Status {
	case 200:
		return ProbeOutput{Status: StatusValid}
	case 401:
		return ProbeOutput{Status: StatusRevoked}
	default:
		return Unknown(r)
	}
}
