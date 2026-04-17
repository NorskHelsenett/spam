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

	writeJSON(w, http.StatusOK, response)
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
