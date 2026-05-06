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
	// FETCH_KEV / FETCH_EPSS pull bulk feeds (CISA KEV, FIRST.org
	// EPSS) into their own tables. Self-rescheduling: each handler
	// enqueues the next run +24 h after success, gated by the
	// ux_jobs_fetch_*_active partial unique index so multi-replica
	// startups can't double-queue.
	JobTypeFetchKEV  JobType = "FETCH_KEV"
	JobTypeFetchEPSS JobType = "FETCH_EPSS"
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

	// SigningPolicy carries the cosign verification config the runner
	// should use when running `cosign verify`. nil / empty means "no
	// verification, just `cosign tree`" — the legacy behaviour. The
	// worker fills this from signing_policy at job-creation time.
	SigningPolicy *ImageScanSigningPolicy `json:"signing_policy,omitempty"`
}

// ImageScanSigningPolicy is the runtime-shaped subset of
// signingpolicy.ResolvedPolicy that travels through the job payload.
// Type matches the package's enum strings ("keyless" | "key").
//
// The KeyPEM is only populated for type='key' policies and is
// transmitted in plaintext over the runner-internal connection
// (already authenticated + scoped per-job by HMAC). Encryption at
// rest in the DB protects against operator/backup leakage; transport
// encryption is the cluster's TLS responsibility.
type ImageScanSigningPolicy struct {
	Type           string `json:"policy_type"`
	Issuer         string `json:"issuer,omitempty"`
	SubjectPattern string `json:"subject_pattern,omitempty"`
	KeyPEM         string `json:"key_pem,omitempty"`
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
