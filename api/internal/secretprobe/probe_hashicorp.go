package secretprobe

import "context"

func init() {
	RegisterOffline("hashicorp-tf-api-token", probeHashiCorp)
	RegisterOffline("hashicorp-tf-password", probeHashiCorp)
	RegisterOffline("vault-batch-token", probeHashiCorp)
	RegisterOffline("vault-service-token", probeHashiCorp)
}

// probeHashiCorp — HashiCorp products (Terraform, Vault) are typically
// self-hosted. Without knowing the server URL we cannot probe externally.
func probeHashiCorp(_ context.Context, _ ProbeContext) ProbeOutput {
	return ProbeOutput{
		Status: StatusUnknown,
		Reason: "server URL unknown — manual review needed",
	}
}
