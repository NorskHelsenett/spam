package secretprobe

import (
	"context"
	"strings"
)

func init() {
	RegisterNetwork("slack-webhook-url", probeSlackWebhook, func(pc ProbeContext) []RequestPreview {
		return []RequestPreview{{
			Method:  "POST",
			URL:     pc.Secret,
			Headers: map[string]string{"Content-Type": "application/json"},
			Body:    "{}",
		}}
	})
	RegisterNetwork("slack-web-hook", probeSlackWebhook, func(pc ProbeContext) []RequestPreview {
		return []RequestPreview{{
			Method:  "POST",
			URL:     pc.Secret,
			Headers: map[string]string{"Content-Type": "application/json"},
			Body:    "{}",
		}}
	})

	authTestDesc := func(pc ProbeContext) []RequestPreview {
		return []RequestPreview{{
			Method:  "POST",
			URL:     "https://slack.com/api/auth.test",
			Headers: map[string]string{"Authorization": "Bearer [REDACTED]", "Content-Type": "application/json"},
		}}
	}
	RegisterNetwork("slack-bot-token", probeSlackBotToken, authTestDesc)
	RegisterNetwork("slack-app-token", probeSlackBotToken, authTestDesc)
}

func probeSlackWebhook(ctx context.Context, pc ProbeContext) ProbeOutput {
	r, err := HTTPPost(ctx, pc.Secret, map[string]string{
		"Content-Type": "application/json",
	}, `{}`)
	if err != nil {
		return ProbeOutput{Status: StatusError, Reason: err.Error()}
	}

	body := strings.ToLower(r.Body)

	switch {
	case r.Status == 400 && (strings.Contains(body, "no_text") || strings.Contains(body, "invalid_payload")):
		return ProbeOutput{Status: StatusValid}
	case r.Status == 403, strings.Contains(body, "token_revoked"), strings.Contains(body, "invalid_token"):
		return ProbeOutput{Status: StatusRevoked}
	case r.Status == 404:
		return ProbeOutput{Status: StatusRevoked, Reason: "webhook not found"}
	default:
		return Unknown(r)
	}
}

func probeSlackBotToken(ctx context.Context, pc ProbeContext) ProbeOutput {
	r, err := HTTPPost(ctx, "https://slack.com/api/auth.test", map[string]string{
		"Authorization": "Bearer " + pc.Secret,
		"Content-Type":  "application/json",
	}, "")
	if err != nil {
		return ProbeOutput{Status: StatusError, Reason: err.Error()}
	}

	if r.Status == 200 {
		if strings.Contains(r.Body, `"ok":true`) {
			return ProbeOutput{Status: StatusValid}
		}
		if strings.Contains(r.Body, "invalid_auth") || strings.Contains(r.Body, "token_revoked") {
			return ProbeOutput{Status: StatusRevoked}
		}
	}
	return Unknown(r)
}
