package secretprobe

import "context"

func init() {
	desc := func(pc ProbeContext) []RequestPreview {
		return []RequestPreview{{
			Method:  "GET",
			URL:     "https://app.terraform.io/api/v2/account/details",
			Headers: map[string]string{"Authorization": "Bearer [REDACTED]"},
		}}
	}
	RegisterNetwork("hashicorp-tf-api-token", probeHashiCorpTF, desc)
	RegisterNetwork("hashicorp-tf-password", probeHashiCorpTF, desc)
	RegisterOffline("vault-batch-token", probeVaultToken)
	RegisterOffline("vault-service-token", probeVaultToken)
}

func probeHashiCorpTF(ctx context.Context, pc ProbeContext) ProbeOutput {
	r, err := HTTPGet(ctx, "https://app.terraform.io/api/v2/account/details", map[string]string{
		"Authorization": "Bearer " + pc.Secret,
		"Content-Type":  "application/vnd.api+json",
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

// probeVaultToken cannot probe without knowing the Vault server URL.
// ProviderBaseURL isn't applicable here since Vault isn't a git provider.
func probeVaultToken(_ context.Context, _ ProbeContext) ProbeOutput {
	return ProbeOutput{
		Status: StatusUnknown,
		Reason: "Vault server URL unknown — manual review needed",
	}
}
