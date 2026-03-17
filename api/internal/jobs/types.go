package jobs

// JobType represents the type of a job.
type JobType = string

const (
	JobTypeCreateRun        JobType = "CREATE_RUN"
	JobTypeRefreshSBOMViews JobType = "REFRESH_SBOM_VIEWS"
	JobTypeOSVScan          JobType = "OSV_SCAN"
	JobTypeTrivyAdhocScan   JobType = "TRIVY_ADHOC_SCAN"
	JobTypeProbeSecrets     JobType = "PROBE_SECRETS"
)

// TrivyAdhocPayload is the payload for TRIVY_ADHOC_SCAN jobs.
type TrivyAdhocPayload struct {
	CronJobName string `json:"cronjob_name"`
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
