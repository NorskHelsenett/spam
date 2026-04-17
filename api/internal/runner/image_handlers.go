package runner

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"strings"
	"time"

	"github.com/NorskHelsenett/spam/internal/artifacts"
	"github.com/NorskHelsenett/spam/internal/imagescan"
	"github.com/NorskHelsenett/spam/internal/jobs"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// imageArtifactSpec maps a form-field name (as uploaded by the runner) to
// the logical category + scanner tuple we persist. Keeping this as data
// rather than a switch keeps the handler dumb and makes it trivial to add
// new scanners (e.g. snyk) later without touching control flow.
type imageArtifactSpec struct {
	field    string // multipart form field name
	category string // logical bucket ("vuln","sbom","secrets","signature","labels")
	scanner  string // producing binary
}

var imageArtifactSpecs = []imageArtifactSpec{
	{"grype", "vuln", "grype"},
	{"trivy_vuln", "vuln", "trivy"},
	{"sbom", "sbom", "syft"}, // trivy SBOM uploads use the same field; scanner recorded by what ran
	{"cosign", "signature", "cosign"},
	{"secrets", "secrets", "betterleaks"},
	{"trivy_secrets", "secrets", "trivy"},
	{"labels", "labels", "crane"},
}

// handleImageResults receives artifacts from an image-scan runner. It
// validates the bearer token, persists every uploaded category in a single
// transaction, feeds SBOMs through the existing artifacts.StoreSBOM pipeline
// (so images appear in /app/components automatically), and stores raw bytes
// for the other categories so future parsers can read them without a
// re-scan.
func (s *Server) handleImageResults(w http.ResponseWriter, r *http.Request) {
	token := extractBearerToken(r)
	if token == "" {
		http.Error(w, "missing authorization", http.StatusUnauthorized)
		return
	}
	claims, err := ValidateRunToken(s.cfg.HMACKey, token)
	if err != nil {
		log.Printf("image results: invalid token: %v", err)
		http.Error(w, "invalid token", http.StatusUnauthorized)
		return
	}

	if err := r.ParseMultipartForm(200 << 20); err != nil { // 200 MB cap
		http.Error(w, "failed to parse form", http.StatusBadRequest)
		return
	}

	scanRunID := r.FormValue("scan_run_id")
	imageDigestID := r.FormValue("image_digest_id")
	if scanRunID == "" || imageDigestID == "" {
		http.Error(w, "scan_run_id and image_digest_id required", http.StatusBadRequest)
		return
	}
	if scanRunID != claims.RunID {
		http.Error(w, "run ID mismatch", http.StatusForbidden)
		return
	}

	// Confirm the job exists and is an image scan; reject uploads for the
	// wrong job type so a compromised token for a CREATE_RUN can't dump
	// garbage into image artifact tables.
	var job jobs.Job
	if err := s.db.WithContext(r.Context()).First(&job, "id = ?", scanRunID).Error; err != nil {
		http.Error(w, "scan run not found", http.StatusNotFound)
		return
	}
	if job.Type != jobs.JobTypeImageScan {
		http.Error(w, "job is not an image scan", http.StatusForbidden)
		return
	}

	now := time.Now().UTC()
	var storedCount int

	err = s.db.WithContext(r.Context()).Transaction(func(tx *gorm.DB) error {
		// Upsert the scan-run row. We do this on first upload rather than at
		// job creation so the row reflects real execution (the K8s job may
		// never get scheduled for reasons outside our control).
		run := imagescan.ImageScanRun{
			ID:            scanRunID,
			ImageDigestID: imageDigestID,
			StartedAt:     &now,
			CreatedAt:     now,
		}
		if err := tx.Where("id = ?", scanRunID).
			Attrs(run).
			FirstOrCreate(&run).Error; err != nil {
			return fmt.Errorf("upsert image scan run: %w", err)
		}

		for _, spec := range imageArtifactSpecs {
			file, header, err := r.FormFile(spec.field)
			if err != nil {
				continue // field not present — scanner didn't run or didn't produce output
			}
			data, readErr := readAllAndClose(file)
			if readErr != nil {
				log.Printf("image results: read %s: %v", spec.field, readErr)
				continue
			}
			if len(data) == 0 {
				continue
			}
			filename := ""
			if header != nil {
				filename = header.Filename
			}

			artifact := imagescan.ImageScanArtifact{
				ID:        uuid.NewString(),
				ScanRunID: scanRunID,
				Category:  spec.category,
				Scanner:   spec.scanner,
				Filename:  filename,
				Size:      int64(len(data)),
				Content:   data,
				CreatedAt: now,
			}
			if err := tx.Create(&artifact).Error; err != nil {
				return fmt.Errorf("persist %s artifact: %w", spec.field, err)
			}
			storedCount++

			// Category-specific parsers.
			switch spec.category {
			case "labels":
				// Parse the OCI `image.source` label once and cache the
				// resolved repo.id on image_digests. Later reads (image
				// detail page, repo→images reverse lookup) avoid
				// re-parsing labels on every request.
				if source := extractSourceLabel(data); source != "" {
					if repoID, err := imagescan.ResolveSourceRepoID(r.Context(), tx, source); err != nil {
						log.Printf("resolve source repo for %s: %v", imageDigestID, err)
					} else if repoID != "" {
						if err := tx.Exec(
							"UPDATE image_digests SET source_repo_id = ? WHERE id = ?",
							repoID, imageDigestID,
						).Error; err != nil {
							log.Printf("update source_repo_id: %v", err)
						}
					}
				}
			case "sbom":
				// SBOMs flow through the existing SBOM pipeline so the
				// image shows up in /app/components immediately.
				hash := sha256.Sum256(data)
				binding := &artifacts.BindingInput{
					AssetType:       artifacts.AssetTypeImageDigest,
					AssetRefID:      imageDigestID,
					Source:          "spam-image-scanner",
					CreatedByUserID: "system",
				}
				if _, _, err := artifacts.StoreSBOM(r.Context(), tx, artifacts.SBOMInput{
					Format:           detectSBOMFormat(filename, data),
					ContentHash:      hash[:],
					ContentBytes:     data,
					IngestedByUserID: "system",
				}, binding); err != nil {
					return fmt.Errorf("store image sbom: %w", err)
				}
			case "vuln":
				if spec.scanner == "grype" {
					n, err := imagescan.ParseAndStoreGrype(r.Context(), tx, imageDigestID, scanRunID, data)
					if err != nil {
						// Parse failures shouldn't abort the whole upload
						// — the raw artifact is still stored so the user
						// can download + retry parsing later.
						log.Printf("grype parse for %s: %v", scanRunID, err)
					} else {
						log.Printf("grype parsed %d finding(s) for %s", n, scanRunID)
					}
				}
				// TODO: trivy_vuln parser goes here once we commit to that format.
			}
		}
		return nil
	})
	if err != nil {
		log.Printf("image results: persist: %v", err)
		http.Error(w, "failed to persist results", http.StatusInternalServerError)
		return
	}

	log.Printf("image scan %s: stored %d artifact(s)", scanRunID, storedCount)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

func readAllAndClose(f multipart.File) ([]byte, error) {
	defer f.Close()
	return io.ReadAll(f)
}

// extractSourceLabel reads the OCI `image.source` label from a
// `crane config` JSON blob. Returns "" when the label isn't present
// or the blob doesn't parse.
func extractSourceLabel(raw []byte) string {
	if len(raw) == 0 {
		return ""
	}
	var config struct {
		Config struct {
			Labels map[string]string `json:"Labels"`
		} `json:"config"`
	}
	if err := json.Unmarshal(raw, &config); err != nil {
		return ""
	}
	return strings.TrimSpace(config.Config.Labels["org.opencontainers.image.source"])
}

// detectSBOMFormat inspects the filename first, then falls back to a cheap
// content sniff. Both syft and trivy default to CycloneDX-JSON in our
// pipeline, so that's the default when detection fails.
func detectSBOMFormat(filename string, data []byte) string {
	lower := strings.ToLower(filename)
	switch {
	case strings.Contains(lower, "spdx"):
		return "spdx-json"
	case strings.Contains(lower, "cyclonedx") || strings.Contains(lower, "cdx"):
		return "cyclonedx-json"
	}
	// Sniff: CycloneDX documents include "bomFormat": "CycloneDX"; SPDX has "spdxVersion".
	head := data
	if len(head) > 512 {
		head = head[:512]
	}
	if strings.Contains(string(head), "CycloneDX") {
		return "cyclonedx-json"
	}
	if strings.Contains(string(head), "spdxVersion") {
		return "spdx-json"
	}
	return "cyclonedx-json"
}
