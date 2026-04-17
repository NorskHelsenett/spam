package uiapi

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/NorskHelsenett/spam/internal/auth"
	"github.com/NorskHelsenett/spam/internal/imagescan"
	"github.com/NorskHelsenett/spam/internal/jobs"
	"gorm.io/gorm"
)

// writeImageScanRunResponse fills a RunResponse for an IMAGE_SCAN job. The
// struct parameter comes from RunGetHandler's local select so we reuse the
// row without re-querying.
func writeImageScanRunResponse(w http.ResponseWriter, r *http.Request, db *gorm.DB, job struct {
	ID         string
	Type       string
	Status     string
	Payload    []byte
	Error      string
	CommitHash string
	CreatedAt  time.Time
	LockedAt   *time.Time
	FinishedAt *time.Time
	K8sJobName string `gorm:"column:k8s_job_name"`
}, runID string) {
	var payload jobs.ImageScanPayload
	if len(job.Payload) > 0 {
		_ = json.Unmarshal(job.Payload, &payload)
	}

	response := RunResponse{
		ID:              job.ID,
		Type:            job.Type,
		Status:          job.Status,
		RepoPath:        imageRefShortDisplay(payload.Registry, payload.Repository, payload.Digest),
		Error:           job.Error,
		CreatedAt:       job.CreatedAt,
		StartedAt:       job.LockedAt,
		FinishedAt:      job.FinishedAt,
		ImageRegistry:   payload.Registry,
		ImageRepository: payload.Repository,
		ImageDigest:     payload.Digest,
		ImageDigestID:   payload.ImageDigestID,
		ImageScanners:   payload.Scanners,
	}

	// Artifact summaries. Content is served on demand via
	// /api/image-scans/:id/artifacts/:artifact_id/download.
	var rows []imagescan.ImageScanArtifact
	if err := db.WithContext(r.Context()).
		Where("scan_run_id = ?", runID).
		Order("created_at ASC").
		Select("id, category, scanner, filename, size, created_at").
		Find(&rows).Error; err != nil {
		log.Printf("image scan artifacts for %s: %v", runID, err)
	} else {
		response.ImageArtifacts = make([]ImageArtifactSummary, 0, len(rows))
		for _, a := range rows {
			response.ImageArtifacts = append(response.ImageArtifacts, ImageArtifactSummary{
				ID:        a.ID,
				Category:  a.Category,
				Scanner:   a.Scanner,
				Filename:  a.Filename,
				Size:      a.Size,
				CreatedAt: a.CreatedAt,
			})
		}
	}

	// Link the image's latest SBOM (stored via existing artifacts pipeline)
	// so the detail page can offer the same "view components" action as
	// repo runs.
	if payload.ImageDigestID != "" {
		var binding struct {
			SBOMID string `gorm:"column:sbom_id"`
		}
		if err := db.WithContext(r.Context()).Table("sbom_bindings").
			Where("asset_type = ? AND asset_ref_id = ?", "IMAGE_DIGEST", payload.ImageDigestID).
			Order("created_at DESC").
			Select("sbom_id").First(&binding).Error; err == nil {
			response.SBOMID = binding.SBOMID
		}
	}

	// Severity summary from the grype parser output.
	var severityRows []struct {
		Severity string
		Count    int
	}
	if err := db.WithContext(r.Context()).
		Table("image_vuln_findings").
		Select("severity, COUNT(*) AS count").
		Where("scan_run_id = ?", runID).
		Group("severity").
		Find(&severityRows).Error; err == nil && len(severityRows) > 0 {
		counts := &ImageVulnSeverityCount{}
		for _, row := range severityRows {
			counts.Total += row.Count
			switch row.Severity {
			case "CRITICAL":
				counts.Critical = row.Count
			case "HIGH":
				counts.High = row.Count
			case "MEDIUM":
				counts.Medium = row.Count
			case "LOW":
				counts.Low = row.Count
			default:
				counts.Unknown += row.Count
			}
		}
		response.ImageVulnCounts = counts
	}

	// Full vuln list (capped at 1000 rows, severity-sorted). For larger
	// findings the UI offers the raw artifact download.
	var findings []imagescan.ImageVulnFinding
	if err := db.WithContext(r.Context()).
		Where("scan_run_id = ?", runID).
		Order(`
			CASE UPPER(severity)
				WHEN 'CRITICAL' THEN 0
				WHEN 'HIGH'     THEN 1
				WHEN 'MEDIUM'   THEN 2
				WHEN 'LOW'      THEN 3
				ELSE 4
			END,
			vuln_id ASC
		`).
		Limit(1000).
		Find(&findings).Error; err == nil {
		response.ImageVulns = make([]ImageVulnListRow, 0, len(findings))
		for _, f := range findings {
			response.ImageVulns = append(response.ImageVulns, ImageVulnListRow{
				VulnID:           f.VulnID,
				Severity:         f.Severity,
				PkgName:          f.PkgName,
				InstalledVersion: f.InstalledVersion,
				FixedVersion:     f.FixedVersion,
				Title:            f.Title,
				Target:           f.Target,
				Scanner:          f.Scanner,
			})
		}
	}

	// Load raw artifact blobs in one round-trip and parse in-process.
	// Small responses (labels, cosign) are fully inlined; secrets are
	// capped at 500 rows (pathological images can have thousands).
	var blobs []imagescan.ImageScanArtifact
	_ = db.WithContext(r.Context()).
		Select("category, scanner, content").
		Where("scan_run_id = ?", runID).
		Find(&blobs).Error

	for _, b := range blobs {
		switch b.Category {
		case "labels":
			response.ImageLabels, response.ImageLabelsMetadata = parseLabelsArtifact(b.Content)
		case "signature":
			response.ImageSignature = parseSignatureArtifact(b.Content)
		case "secrets":
			if b.Scanner == "betterleaks" {
				response.ImageSecrets = parseBetterleaksArtifact(b.Content, 500)
			}
		}
	}

	// SBOM component count (cheap lookup; frontend can hit /api/sboms/{id}
	// for the full list if the operator wants to drill in).
	if response.SBOMID != "" {
		var componentCount int64
		if err := db.WithContext(r.Context()).
			Table("sbom_component_view").
			Where("sbom_id = ? AND is_root = false", response.SBOMID).
			Count(&componentCount).Error; err == nil {
			response.SBOMComponentCount = int(componentCount)
		}
	}

	writeJSON(w, http.StatusOK, response)
}

// parseLabelsArtifact extracts labels + OCI metadata from a raw
// `crane config` JSON blob. Returns (nil, nil) when the blob can't be
// parsed — we never want a bad artifact to sink the whole detail page.
func parseLabelsArtifact(raw []byte) (map[string]string, *ImageOCIMetadata) {
	if len(raw) == 0 {
		return nil, nil
	}
	var config struct {
		Architecture string `json:"architecture"`
		OS           string `json:"os"`
		Created      string `json:"created"`
		Author       string `json:"author"`
		Config       struct {
			Labels map[string]string `json:"Labels"`
		} `json:"config"`
	}
	if err := json.Unmarshal(raw, &config); err != nil {
		return nil, nil
	}
	meta := &ImageOCIMetadata{
		Created:      config.Created,
		Architecture: config.Architecture,
		OS:           config.OS,
		Author:       config.Author,
	}
	return config.Config.Labels, meta
}

// parseSignatureArtifact reads the JSON our runner writes for the cosign
// category (see runner/imagescan/imagescan.go::runSignature).
func parseSignatureArtifact(raw []byte) *ImageSignatureInfo {
	if len(raw) == 0 {
		return nil
	}
	var payload struct {
		Signed   bool   `json:"signed"`
		Verified bool   `json:"verified"`
		Error    string `json:"error"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return nil
	}
	return &ImageSignatureInfo{
		Signed:   payload.Signed,
		Verified: payload.Verified,
		Error:    payload.Error,
	}
}

// parseBetterleaksArtifact decodes the betterleaks JSON report, truncates
// matches so one big payload doesn't balloon the response, and caps the
// total returned row count. Field names follow betterleaks' gitleaks-
// compatible schema.
func parseBetterleaksArtifact(raw []byte, maxRows int) []ImageSecretListRow {
	if len(raw) == 0 {
		return nil
	}
	var entries []struct {
		RuleID      string `json:"RuleID"`
		Description string `json:"Description"`
		File        string `json:"File"`
		StartLine   int    `json:"StartLine"`
		Match       string `json:"Match"`
	}
	if err := json.Unmarshal(raw, &entries); err != nil {
		return nil
	}
	if len(entries) == 0 {
		return nil
	}
	if maxRows > 0 && len(entries) > maxRows {
		entries = entries[:maxRows]
	}
	out := make([]ImageSecretListRow, 0, len(entries))
	for _, e := range entries {
		match := e.Match
		if len(match) > 160 {
			match = match[:160] + "…"
		}
		out = append(out, ImageSecretListRow{
			RuleID:      e.RuleID,
			Description: e.Description,
			File:        e.File,
			StartLine:   e.StartLine,
			Match:       match,
		})
	}
	return out
}

// ImageScanArtifactDownloadHandler streams the raw bytes of a single
// image-scan artifact by ID. The job ID path component is validated so a
// guessed artifact UUID from another scan isn't accessible here.
// GET /api/image-scans/{job_id}/artifacts/{artifact_id}/download
func ImageScanArtifactDownloadHandler(db *gorm.DB, authService *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if requireAuth(w, r, authService) == nil {
			return
		}
		jobID := r.PathValue("job_id")
		artifactID := r.PathValue("artifact_id")
		if jobID == "" || artifactID == "" {
			http.Error(w, "job_id and artifact_id required", http.StatusBadRequest)
			return
		}

		var art imagescan.ImageScanArtifact
		if err := db.WithContext(r.Context()).
			Where("id = ? AND scan_run_id = ?", artifactID, jobID).
			First(&art).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				http.Error(w, "artifact not found", http.StatusNotFound)
				return
			}
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		filename := art.Filename
		if filename == "" {
			filename = art.Category + "-" + art.Scanner + ".json"
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", "attachment; filename="+filename)
		_, _ = w.Write(art.Content)
	}
}
