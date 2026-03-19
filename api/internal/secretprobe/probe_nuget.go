package secretprobe

import "context"

func init() {
	desc := func(pc ProbeContext) []RequestPreview {
		return []RequestPreview{{
			Method:  "GET",
			URL:     "https://www.nuget.org/api/v2/verifykey/",
			Headers: map[string]string{"X-NuGet-ApiKey": "[REDACTED]"},
		}}
	}
	RegisterNetwork("nuget-api-key", probeNuGetAPIKey, desc)
	RegisterNetwork("nuget-config-password", probeNuGetAPIKey, desc)
}

func probeNuGetAPIKey(ctx context.Context, pc ProbeContext) ProbeOutput {
	r, err := HTTPGet(ctx, "https://www.nuget.org/api/v2/verifykey/", map[string]string{
		"X-NuGet-ApiKey": pc.Secret,
	})
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
