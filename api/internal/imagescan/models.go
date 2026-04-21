package imagescan

import "time"

// ImageScanRun is the per-job record for a single IMAGE_SCAN execution. Its
// ID matches the jobs.Job ID so /app/runs and image-scan views can join on
// the same key. K8s coordinates are recorded for observability; the Job row
// remains the source of truth for status.
type ImageScanRun struct {
	ID            string     `gorm:"primaryKey;size:36"`
	ImageDigestID string     `gorm:"size:36;index;not null"`
	K8sJobName    string     `gorm:"size:128"`
	K8sNamespace  string     `gorm:"size:128"`
	StartedAt     *time.Time `gorm:"index"`
	FinishedAt    *time.Time
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

// ImageVulnFinding is one CVE match discovered by a vulnerability scanner
// (grype by default, trivy when opted in). Rows are written by the upload
// handler's grype parser on every scan; the API consumes them from
// /app/vulnerabilities via a UNION with repo-sourced vulns.
//
// Keyed by (image_digest_id, vuln_id, pkg_name, installed_version) so a
// re-scan of the same digest overwrites in place instead of duplicating.
// Severity is UPPER-cased at insert time to match how OSV / Trivy rows are
// stored.
type ImageVulnFinding struct {
	ID               string    `gorm:"primaryKey;size:36"`
	ImageDigestID    string    `gorm:"size:36;index:idx_image_vuln_lookup,priority:1;not null"`
	ScanRunID        string    `gorm:"size:36;index;not null"`
	Scanner          string    `gorm:"size:32;not null"`
	VulnID           string    `gorm:"size:128;index:idx_image_vuln_lookup,priority:2;not null"`
	Severity         string    `gorm:"size:16;index"`
	PkgName          string    `gorm:"size:255;index:idx_image_vuln_lookup,priority:3"`
	InstalledVersion string    `gorm:"size:255;index:idx_image_vuln_lookup,priority:4"`
	FixedVersion     string    `gorm:"size:255"`
	Title            string    `gorm:"size:512"`
	Description      string    `gorm:"type:text"`
	Target           string    `gorm:"size:512"` // filesystem path / layer where the package was found
	CreatedAt        time.Time
}

// ImageScanArtifact stores a single scanner output blob produced by one
// ImageScanRun. Storing raw bytes keyed by (scan_run, category, scanner) lets
// parsers evolve independently — a future vuln parser reads the `grype`
// category, a signature parser reads `cosign`, and so on, without needing to
// backfill data.
//
// Category is the logical bucket: "vuln", "sbom", "secrets", "signature",
// "labels", "trivy_vuln", "trivy_secrets". Scanner names the actual binary
// that produced the artifact: "grype", "syft", "cosign", "betterleaks",
// "crane", "trivy".
type ImageScanArtifact struct {
	ID        string    `gorm:"primaryKey;size:36"`
	ScanRunID string    `gorm:"size:36;index;not null"`
	Category  string    `gorm:"size:32;index;not null"`
	Scanner   string    `gorm:"size:32;not null"`
	Filename  string    `gorm:"size:255"`
	Size      int64     `gorm:"not null"`
	Content   []byte    `gorm:"type:bytea"`
	CreatedAt time.Time
}
