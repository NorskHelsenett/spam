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
