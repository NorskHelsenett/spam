package jobs

// JobType represents the type of a job.
type JobType = string

const (
	JobTypeCreateRun        JobType = "CREATE_RUN"
	JobTypeRefreshSBOMViews JobType = "REFRESH_SBOM_VIEWS"
	JobTypeOSVScan          JobType = "OSV_SCAN"
	JobTypeSBOMAdhocScan    JobType = "SBOM_ADHOC_SCAN"
	JobTypeProbeSecrets     JobType = "PROBE_SECRETS"
	JobTypeImageScan        JobType = "IMAGE_SCAN"
	JobTypeVulnMetaFetch    JobType = "VULN_META_FETCH"
)

// VulnMetaFetchPayload is the payload for VULN_META_FETCH jobs —
// one vuln_id per job. Kept single-id so a flaky external fetch
// only retries one ID at a time and the worker can parallelize
// across IDs by claiming multiple jobs.
type VulnMetaFetchPayload struct {
	VulnID string `json:"vuln_id"`
}

// SBOMAdhocPayload is the payload for SBOM_ADHOC_SCAN jobs. The ad-hoc
// run clones the SBOM scanner CronJob's pod template to force a scan
// sweep on demand; the cronjob name is read from the worker's env var
// by default, but can be overridden per-job via CronJobName.
type SBOMAdhocPayload struct {
	CronJobName string `json:"cronjob_name"`
}

// ImageScanPayload is the payload for IMAGE_SCAN jobs.
// Scanner selection is a map keyed by scan category:
//
//	"vuln"      -> "grype" (default) | "trivy"
//	"sbom"      -> "syft"  (default) | "trivy"
//	"secrets"   -> "betterleaks" (default) | "trivy"
//	"signature" -> "cosign" (default)
//	"labels"    -> "crane"  (default)
//
// An empty or missing key falls back to the default. The runner is the source
// of truth for the registry of scanners; the API only forwards names.
type ImageScanPayload struct {
	ImageDigestID string            `json:"image_digest_id"`
	Registry      string            `json:"registry"`
	Repository    string            `json:"repository"`
	Digest        string            `json:"digest"`
	Scanners      map[string]string `json:"scanners,omitempty"`
}

// CreateRunPayload is the payload for CREATE_RUN jobs.
// This is the canonical definition - do not duplicate elsewhere.
type CreateRunPayload struct {
	RepoID     string `json:"repo_id,omitempty"`
	ProviderID string `json:"provider_id,omitempty"`
	Provider   string `json:"provider,omitempty"`
	CloneURL   string `json:"clone_url"`
	Ref        string `json:"ref,omitempty"`
	CommitSHA  string `json:"commit_sha,omitempty"`
	// RepoDisabled indicates the provider reported this repository as disabled.
	RepoDisabled bool `json:"repo_disabled,omitempty"`
}
