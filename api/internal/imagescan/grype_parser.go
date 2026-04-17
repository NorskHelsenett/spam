package imagescan

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// grypeReport models only the fields we consume. Grype's full schema is
// large and versioned; sticking to the well-known matches[].* shape keeps
// the parser tolerant to minor upstream changes.
type grypeReport struct {
	Matches []struct {
		Vulnerability struct {
			ID          string   `json:"id"`
			Severity    string   `json:"severity"`
			Description string   `json:"description"`
			URLs        []string `json:"urls"`
			Fix         struct {
				Versions []string `json:"versions"`
				State    string   `json:"state"`
			} `json:"fix"`
		} `json:"vulnerability"`
		Artifact struct {
			Name      string `json:"name"`
			Version   string `json:"version"`
			Type      string `json:"type"`
			PURL      string `json:"purl"`
			Locations []struct {
				Path string `json:"path"`
			} `json:"locations"`
		} `json:"artifact"`
	} `json:"matches"`
}

// ParseAndStoreGrype consumes raw grype JSON output and upserts findings
// into image_vuln_findings keyed by (image_digest_id, vuln_id, pkg, ver).
// Prior findings for the same image_digest_id are deleted first so a
// re-scan reflects the current DB / fix state rather than accumulating
// stale rows.
//
// The caller is expected to pass `tx` — we do deletes + inserts in one
// transaction scoped to this one image digest so a parse failure mid-scan
// doesn't leave half-stored findings.
func ParseAndStoreGrype(ctx context.Context, tx *gorm.DB, imageDigestID, scanRunID string, raw []byte) (int, error) {
	if imageDigestID == "" || scanRunID == "" {
		return 0, fmt.Errorf("imageDigestID and scanRunID required")
	}
	var report grypeReport
	if err := json.Unmarshal(raw, &report); err != nil {
		return 0, fmt.Errorf("unmarshal grype report: %w", err)
	}

	if err := tx.WithContext(ctx).
		Where("image_digest_id = ? AND scanner = ?", imageDigestID, "grype").
		Delete(&ImageVulnFinding{}).Error; err != nil {
		return 0, fmt.Errorf("clear prior grype findings: %w", err)
	}

	now := time.Now().UTC()
	findings := make([]ImageVulnFinding, 0, len(report.Matches))
	for _, m := range report.Matches {
		if m.Vulnerability.ID == "" || m.Artifact.Name == "" {
			continue
		}
		fixed := ""
		if len(m.Vulnerability.Fix.Versions) > 0 {
			fixed = m.Vulnerability.Fix.Versions[0]
		}
		target := ""
		if len(m.Artifact.Locations) > 0 {
			target = m.Artifact.Locations[0].Path
		}
		findings = append(findings, ImageVulnFinding{
			ID:               uuid.NewString(),
			ImageDigestID:    imageDigestID,
			ScanRunID:        scanRunID,
			Scanner:          "grype",
			VulnID:           m.Vulnerability.ID,
			Severity:         strings.ToUpper(strings.TrimSpace(m.Vulnerability.Severity)),
			PkgName:          m.Artifact.Name,
			InstalledVersion: m.Artifact.Version,
			FixedVersion:     fixed,
			Title:            "", // grype doesn't expose a title field; description carries the long form
			Description:      truncate(m.Vulnerability.Description, 4096),
			Target:           target,
			CreatedAt:        now,
		})
	}

	if len(findings) == 0 {
		return 0, nil
	}
	// CreateInBatches keeps single-insert-size reasonable on large images
	// (alpine base + app can produce thousands of matches).
	if err := tx.WithContext(ctx).CreateInBatches(findings, 200).Error; err != nil {
		return 0, fmt.Errorf("insert grype findings: %w", err)
	}
	return len(findings), nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
