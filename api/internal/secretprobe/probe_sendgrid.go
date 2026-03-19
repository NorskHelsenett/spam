package secretprobe

import "context"

func init() {
	RegisterNetwork("sendgrid-api-token", probeSendGrid, func(pc ProbeContext) []RequestPreview {
		return []RequestPreview{{
			Method:  "GET",
			URL:     "https://api.sendgrid.com/v3/scopes",
			Headers: map[string]string{"Authorization": "Bearer [REDACTED]"},
		}}
	})
}

func probeSendGrid(ctx context.Context, pc ProbeContext) ProbeOutput {
	r, err := HTTPGet(ctx, "https://api.sendgrid.com/v3/scopes", map[string]string{
		"Authorization": "Bearer " + pc.Secret,
	})
	if err != nil {
		return ProbeOutput{Status: StatusError, Reason: err.Error()}
	}

	switch r.Status {
	case 200:
		return ProbeOutput{Status: StatusValid}
	case 401, 403:
		return ProbeOutput{Status: StatusRevoked}
	default:
		return Unknown(r)
	}
}
