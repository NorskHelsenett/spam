package vulnerabilities

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// TrivyScanLease holds an in-progress scan claim for a single SBOM.
// The lease expires after 30 min so pods that crash release the slot.
type TrivyScanLease struct {
	SBOMID    string    `gorm:"primaryKey;column:sbom_id"`
	LeasedAt  time.Time `gorm:"column:leased_at;autoCreateTime"`
	LeasedBy  string    `gorm:"column:leased_by;size:256"`
	ExpiresAt time.Time `gorm:"column:expires_at"`
}

func (TrivyScanLease) TableName() string { return "trivy_scan_leases" }

// TrivyScanResult stores the processed output of a single Trivy SBOM scan.
type TrivyScanResult struct {
	ID            string          `gorm:"primaryKey;size:36"`
	SBOMID        string          `gorm:"column:sbom_id;uniqueIndex:ux_trivy_scan_results_sbom_id;size:36;not null"`
	RepoID        string          `gorm:"column:repo_id;index:idx_trivy_scan_results_repo_id;size:36;not null"`
	ScannedAt     time.Time       `gorm:"column:scanned_at;index:idx_trivy_scan_results_scanned_at"`
	SchemaVersion int             `gorm:"column:schema_version"`
	ArtifactName  string          `gorm:"column:artifact_name;size:512"`
	CriticalCount int             `gorm:"column:critical_count"`
	HighCount     int             `gorm:"column:high_count"`
	MediumCount   int             `gorm:"column:medium_count"`
	LowCount      int             `gorm:"column:low_count"`
	UnknownCount  int             `gorm:"column:unknown_count"`
	RawJSON       json.RawMessage `gorm:"column:raw_json;type:jsonb"`
	CreatedAt     time.Time       `gorm:"column:created_at;autoCreateTime"`
}

func (TrivyScanResult) TableName() string { return "trivy_scan_results" }

// SBOMScanJob is the data returned by GetNextSBOMToScan.
type SBOMScanJob struct {
	SBOMID   string
	RepoID   string
	Format   string
	RepoSlug string
}

// TrivyReport is a minimal representation of Trivy JSON output used to
// extract severity counts. The full raw document is stored as-is.
type TrivyReport struct {
	SchemaVersion int    `json:"SchemaVersion"`
	ArtifactName  string `json:"ArtifactName"`
	Results       []struct {
		Vulnerabilities []struct {
			Severity string `json:"Severity"`
		} `json:"Vulnerabilities"`
	} `json:"Results"`
}

const leaseDuration = 30 * time.Minute

// GetNextSBOMToScan leases the next un-scanned SBOM and returns its metadata.
// Returns (nil, false, nil) when the queue is empty.
func GetNextSBOMToScan(ctx context.Context, db *gorm.DB, leasedBy string) (*SBOMScanJob, bool, error) {
	var job SBOMScanJob

	err := db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		// Find the oldest SBOM that has no result and no active lease.
		type row struct {
			SBOMID   string
			RepoID   string
			Format   string
			RepoSlug string
		}
		var r row
		res := tx.Raw(`
			SELECT
				s.id                                       AS sbom_id,
				COALESCE(rc.repo_id, '')                   AS repo_id,
				s.format,
				COALESCE(repo.org || '/' || repo.slug, '') AS repo_slug
			FROM sboms s
			INNER JOIN sbom_bindings sb  ON sb.sbom_id = s.id
			LEFT JOIN repo_commits  rc  ON rc.id = sb.asset_ref_id AND sb.asset_type = 'REPO_COMMIT'
			LEFT JOIN repos         repo ON repo.id = rc.repo_id
			LEFT JOIN trivy_scan_results tsr ON tsr.sbom_id = s.id
			LEFT JOIN trivy_scan_leases  tsl ON tsl.sbom_id = s.id AND tsl.expires_at > now()
			WHERE tsr.id IS NULL
			  AND tsl.sbom_id IS NULL
			  AND (
			    sb.asset_type != 'REPO_COMMIT'
			    OR NOT EXISTS (
			      SELECT 1
			      FROM sbom_bindings sb2
			      INNER JOIN repo_commits rc2 ON rc2.id = sb2.asset_ref_id AND sb2.asset_type = 'REPO_COMMIT'
			      WHERE rc2.repo_id = rc.repo_id
			        AND rc2.created_at > rc.created_at
			    )
			  )
			ORDER BY s.created_at ASC
			LIMIT 1
			FOR UPDATE OF s SKIP LOCKED
		`).Scan(&r)
		if res.Error != nil {
			return res.Error
		}
		if r.SBOMID == "" {
			return nil // queue empty
		}

		// Insert lease.
		now := time.Now().UTC()
		lease := TrivyScanLease{
			SBOMID:    r.SBOMID,
			LeasedAt:  now,
			LeasedBy:  leasedBy,
			ExpiresAt: now.Add(leaseDuration),
		}
		if err := tx.Clauses(clause.OnConflict{UpdateAll: true}).Create(&lease).Error; err != nil {
			return fmt.Errorf("create lease: %w", err)
		}

		job = SBOMScanJob{
			SBOMID:   r.SBOMID,
			RepoID:   r.RepoID,
			Format:   r.Format,
			RepoSlug: r.RepoSlug,
		}
		return nil
	})
	if err != nil {
		return nil, false, err
	}
	if job.SBOMID == "" {
		return nil, false, nil
	}
	return &job, true, nil
}

// StoreScanResult persists a Trivy scan result and removes the lease.
func StoreScanResult(ctx context.Context, db *gorm.DB, sbomID, repoID string, report TrivyReport, raw json.RawMessage) error {
	counts := countSeverities(report)

	result := TrivyScanResult{
		ID:            uuid.NewString(),
		SBOMID:        sbomID,
		RepoID:        repoID,
		ScannedAt:     time.Now().UTC(),
		SchemaVersion: report.SchemaVersion,
		ArtifactName:  report.ArtifactName,
		CriticalCount: counts[0],
		HighCount:     counts[1],
		MediumCount:   counts[2],
		LowCount:      counts[3],
		UnknownCount:  counts[4],
		RawJSON:       raw,
	}

	return db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Save(&result).Error; err != nil {
			return fmt.Errorf("save result: %w", err)
		}
		if err := tx.Delete(&TrivyScanLease{}, "sbom_id = ?", sbomID).Error; err != nil {
			return fmt.Errorf("delete lease: %w", err)
		}
		return nil
	})
}

// CleanExpiredLeases removes leases whose expiry has passed.
func CleanExpiredLeases(ctx context.Context, db *gorm.DB) error {
	return db.WithContext(ctx).
		Where("expires_at <= ?", time.Now().UTC()).
		Delete(&TrivyScanLease{}).Error
}

// countSeverities tallies [critical, high, medium, low, unknown] across all results.
func countSeverities(report TrivyReport) [5]int {
	var counts [5]int
	for _, res := range report.Results {
		for _, v := range res.Vulnerabilities {
			switch v.Severity {
			case "CRITICAL":
				counts[0]++
			case "HIGH":
				counts[1]++
			case "MEDIUM":
				counts[2]++
			case "LOW":
				counts[3]++
			default:
				counts[4]++
			}
		}
	}
	return counts
}
