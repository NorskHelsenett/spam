package uiapi

import "time"

type RepoMetadataResponse struct {
	Repo            RepoMetadataRepo            `json:"repo"`
	LatestCommit    *RepoMetadataCommit         `json:"latest_commit,omitempty"`
	Runs            RepoMetadataRuns            `json:"runs"`
	SBOM            RepoMetadataSBOM            `json:"sbom"`
	Dependencies    RepoMetadataDependencies    `json:"dependencies"`
	Secrets         RepoMetadataSecrets         `json:"secrets"`
	Hygiene         RepoMetadataHygiene         `json:"hygiene"`
	Vulnerabilities RepoMetadataVulnerabilities `json:"vulnerabilities"`
}

type RepoMetadataRepo struct {
	ID            string `json:"id"`
	Provider      string `json:"provider"`
	Org           string `json:"org"`
	Slug          string `json:"slug"`
	URL           string `json:"url,omitempty"`
	DefaultBranch string `json:"default_branch,omitempty"`
	IsPrivate     bool   `json:"is_private,omitempty"`
	IsArchived    bool   `json:"is_archived,omitempty"`
	Language      string `json:"language,omitempty"`
	UpdatedAt     string `json:"updated_at,omitempty"`
}

type RepoMetadataCommit struct {
	SHA         string `json:"sha"`
	Author      string `json:"author,omitempty"`
	Message     string `json:"message,omitempty"`
	CommittedAt string `json:"committed_at,omitempty"`
	URL         string `json:"url,omitempty"`
}

type RepoMetadataRuns struct {
	Total    int64                    `json:"total"`
	Latest   *RepoMetadataRunSummary  `json:"latest,omitempty"`
	Timeline []RepoMetadataRunSummary `json:"timeline"`
}

type RepoMetadataRunSummary struct {
	ID         string   `json:"id"`
	Status     string   `json:"status"`
	StartedAt  string   `json:"started_at,omitempty"`
	FinishedAt string   `json:"finished_at,omitempty"`
	DurationMs int64    `json:"duration_ms,omitempty"`
	CommitSHA  string   `json:"commit_sha,omitempty"`
	Artifacts  []string `json:"artifacts,omitempty"`
}

type RepoMetadataSBOM struct {
	Latest *RepoMetadataSBOMItem `json:"latest,omitempty"`
}

type RepoMetadataSBOMItem struct {
	ID             string `json:"id"`
	CreatedAt      string `json:"created_at,omitempty"`
	Format         string `json:"format,omitempty"`
	ComponentCount int64  `json:"component_count,omitempty"`
	DownloadURL    string `json:"download_url,omitempty"`
}

type RepoMetadataDependencies struct {
	Total        int64 `json:"total,omitempty"`
	FromSBOM     int64 `json:"from_sbom,omitempty"`
	FromManifest int64 `json:"from_manifest,omitempty"`
}

type RepoMetadataSecrets struct {
	LatestCount   int64  `json:"latest_count,omitempty"`
	LatestRunID   string `json:"latest_run_id,omitempty"`
	LastScannedAt string `json:"last_scanned_at,omitempty"`
}

type RepoMetadataHygiene struct {
	Maintainers    *bool `json:"maintainers,omitempty"`
	Codeowners     *bool `json:"codeowners,omitempty"`
	License        *bool `json:"license,omitempty"`
	Readme         *bool `json:"readme,omitempty"`
	SecurityPolicy *bool `json:"security_policy,omitempty"`
}

type RepoMetadataVulnerabilities struct {
	Summary *RepoMetadataVulnSummary `json:"summary,omitempty"`
	List    []RepoMetadataVulnItem   `json:"list,omitempty"`
}

type RepoMetadataVulnSummary struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
}

type RepoMetadataVulnItem struct {
	ID       string `json:"id"`
	Severity string `json:"severity"`
	Package  string `json:"package"`
	Version  string `json:"version"`
	FixedIn  string `json:"fixed_in,omitempty"`
}

func formatTimePtr(t *time.Time) string {
	if t == nil {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}
