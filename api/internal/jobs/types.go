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
	// FETCH_DEP_HEALTH refreshes third-party library health metadata
	// (last activity, archived/deprecated flags, latest version,
	// stars, issue velocity) from public registries + GitHub/GitLab.
	// Same self-rescheduling pattern as KEV/EPSS but on a weekly
	// cadence — packages don't change health that fast and rate-
	// limited registries thank us for the lower QPS.
	JobTypeFetchDepHealth JobType = "FETCH_DEP_HEALTH"
	// ADVISORY_BACKFILL generates LLM advisories for every fix_now
	// asset whose cached advisory is missing or stale, without the
	// background worker's per-cycle batch cap. Admin-triggered from
	// /admin/ai; the partial unique index keeps one active at a time.
	// Payload (AdvisoryBackfillPayload) may set replace to regenerate
	// every urgent-tier advisory regardless of freshness.
	JobTypeAdvisoryBackfill JobType = "ADVISORY_BACKFILL"
	// DB_MAINTENANCE runs a safe-by-default Postgres maintenance op
	// (ANALYZE or VACUUM ANALYZE) on a single named table. Driven from
	// the admin Database page. We deliberately do not expose VACUUM
	// FULL or REINDEX here — those acquire AccessExclusiveLock and
	// belong behind a separate, explicit code path.
	JobTypeDBMaintenance JobType = "DB_MAINTENANCE"
	// PRUNE_JOBS deletes terminal (SUCCEEDED/FAILED) job rows older than
	// the retention window so the queue table doesn't grow unbounded —
	// VULN_META_FETCH alone leaves hundreds of thousands of SUCCEEDED rows
	// over a few months. Self-rescheduling on a daily cadence, gated by
	// ux_jobs_prune_jobs_active so replicas can't double-queue.
	JobTypePruneJobs JobType = "PRUNE_JOBS"
	// REFRESH_MV is the scheduled driver for the expensive materialized-view
	// families (unified vuln + asset_risk cascade, and the SBOM views). It
	// fires their debounced TriggerRefresh entry points on a fixed cadence
	// so refresh frequency is driven by a predictable schedule rather than
	// by scanner-agent ingestion volume. Self-rescheduling, gated by
	// ux_jobs_refresh_mv_active.
	JobTypeRefreshMV JobType = "REFRESH_MV"
)

// AdvisoryBackfillPayload is the payload for ADVISORY_BACKFILL jobs.
// Replace=false (or an empty payload — pre-flag jobs) is the
// original backlog drain: fix_now assets with a missing/stale
// advisory. Replace=true regenerates every fix_now + this_week
// advisory from scratch, replacing whatever is cached — needed when
// the prompt or payload shape changes, since the signals hash only
// tracks vuln data.
type AdvisoryBackfillPayload struct {
	Replace bool `json:"replace,omitempty"`
}

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
//
// The four endpoint URLs let an org point cosign at self-hosted
// Sigstore (Fulcio/Rekor) or a separate signature registry without
// patching the runner. Empty values keep cosign on its public-
// Sigstore defaults.
type ImageScanSigningPolicy struct {
	Type           string `json:"policy_type"`
	Issuer         string `json:"issuer,omitempty"`
	SubjectPattern string `json:"subject_pattern,omitempty"`
	KeyPEM         string `json:"key_pem,omitempty"`

	SignatureRepository string `json:"signature_repository,omitempty"`
	FulcioURL           string `json:"fulcio_url,omitempty"`
	RekorURL            string `json:"rekor_url,omitempty"`
	TUFMirrorURL        string `json:"tuf_mirror_url,omitempty"`
}

// DBMaintenanceOp enumerates the maintenance operations DB_MAINTENANCE
// jobs may run. Keep this list narrow on purpose — every new op
// expands the surface area for a misbehaving SQL to lock the DB.
type DBMaintenanceOp string

const (
	DBMaintenanceOpAnalyze       DBMaintenanceOp = "analyze"
	DBMaintenanceOpVacuumAnalyze DBMaintenanceOp = "vacuum_analyze"
)

// DBMaintenancePayload is the payload for DB_MAINTENANCE jobs. Schema +
// Table are re-validated against pg_catalog inside the worker before
// the statement is built, so the column identifier interpolation never
// touches a string the caller controls without a round-trip through
// pg_catalog first.
type DBMaintenancePayload struct {
	Schema    string          `json:"schema"`
	Table     string          `json:"table"`
	Operation DBMaintenanceOp `json:"operation"`
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
