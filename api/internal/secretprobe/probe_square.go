package secretprobe

import "context"

func init() {
	RegisterNetwork("square-access-token", probeSquare, func(pc ProbeContext) []RequestPreview {
		return []RequestPreview{{
			Method:  "GET",
			URL:     "https://connect.squareup.com/v2/locations",
			Headers: map[string]string{"Authorization": "Bearer [REDACTED]"},
		}}
	})
}

func probeSquare(ctx context.Context, pc ProbeContext) ProbeOutput {
	r, err := HTTPGet(ctx, "https://connect.squareup.com/v2/locations", map[string]string{
		"Authorization": "Bearer " + pc.Secret,
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
