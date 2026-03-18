package secretprobe

import (
	"context"
	"encoding/json"
)

func init() {
	RegisterNetwork("huggingface-access-token", probeHuggingFace, func(pc ProbeContext) []RequestPreview {
		return []RequestPreview{{
			Method:  "GET",
			URL:     "https://huggingface.co/api/whoami-v2",
			Headers: map[string]string{"Authorization": "Bearer [REDACTED]"},
		}}
	})
}

func probeHuggingFace(ctx context.Context, pc ProbeContext) ProbeOutput {
	r, err := HTTPGet(ctx, "https://huggingface.co/api/whoami-v2", map[string]string{
		"Authorization": "Bearer " + pc.Secret,
	})
	if err != nil {
		return ProbeOutput{Status: StatusError, Reason: err.Error()}
	}

	switch r.Status {
	case 200:
		meta := map[string]any{}
		var body struct {
			Name string `json:"name"`
			Type string `json:"type"`
		}
		if json.Unmarshal([]byte(r.Body), &body) == nil {
			if body.Name != "" {
				meta["name"] = body.Name
			}
			if body.Type != "" {
				meta["type"] = body.Type
			}
		}
		return ProbeOutput{Status: StatusValid, Metadata: meta}
	case 401:
		return ProbeOutput{Status: StatusRevoked}
	default:
		return Unknown(r)
	}
}
