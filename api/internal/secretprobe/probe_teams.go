package secretprobe

import (
	"context"
	"strings"
)

func init() {
	RegisterNetwork("microsoft-teams-webhook", probeTeamsWebhook, func(pc ProbeContext) []RequestPreview {
		return []RequestPreview{{
			Method:  "POST",
			URL:     pc.Secret,
			Headers: map[string]string{"Content-Type": "application/json"},
			Body:    "{}",
		}}
	})
}

func probeTeamsWebhook(ctx context.Context, pc ProbeContext) ProbeOutput {
	// Send an empty JSON object — Teams rejects it with 400 if the webhook
	// is active, but returns 404 or 410 if it has been removed.
	r, err := HTTPPost(ctx, pc.Secret, map[string]string{
		"Content-Type": "application/json",
	}, `{}`)
	if err != nil {
		return ProbeOutput{Status: StatusError, Reason: err.Error()}
	}

	body := strings.ToLower(r.Body)

	switch {
	case r.Status == 400 || r.Status == 200:
		return ProbeOutput{Status: StatusValid}
	case r.Status == 404, r.Status == 410:
		return ProbeOutput{Status: StatusRevoked, Reason: "webhook not found"}
	case strings.Contains(body, "invalid") || strings.Contains(body, "expired"):
		return ProbeOutput{Status: StatusRevoked}
	default:
		return Unknown(r)
	}
}
