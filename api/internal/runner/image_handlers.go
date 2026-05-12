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

	// Pre-parse the labels artifact so SBOM bindings can carry the
	// commit SHA (`org.opencontainers.image.revision`). The artifact
	// loop below processes `sbom` before `labels` (ordered by scanner
	// runtime cost, not dependency), so without this pre-read the
	// binding would be created with commit_sha='' and the repo-page
	// Commits tab couldn't join commit → image → live workloads.
	var commitRevision string
	if labelsFile, _, err := r.FormFile("labels"); err == nil {
		if raw, err := readAllAndClose(labelsFile); err == nil {
			commitRevision = extractRevisionLabel(raw)
		}
	}

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
				//
				// Resolution or UPDATE failures are logged rather than
				// failing the whole upload — the artifact bytes are fine,
				// only the repo link is missing, and BackfillSourceRepoIDs
				// in the worker picks up any image_digests row with a
				// NULL source_repo_id on its next tick. The log lines
				// below include both IDs so orphaned scans are grep-able.
				if source := extractSourceLabel(data); source != "" {
					if repoID, err := imagescan.ResolveSourceRepoID(r.Context(), tx, source); err != nil {
						log.Printf("image results: resolve source_repo_id failed (will retry via backfill): image_digest_id=%s source=%s err=%v", imageDigestID, source, err)
					} else if repoID != "" {
						if err := tx.Exec(
							"UPDATE image_digests SET source_repo_id = ? WHERE id = ?",
							repoID, imageDigestID,
						).Error; err != nil {
							log.Printf("image results: update source_repo_id failed (will retry via backfill): image_digest_id=%s repo_id=%s err=%v", imageDigestID, repoID, err)
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
					CommitSHA:       commitRevision,
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
			case "signature":
				// Verify-against-policy result: when verified=true, flip
				// image_digests.verified_source so the existing ACL
				// inheritance gate (acl/scope.go ReadableImageClause)
				// starts trusting source_repo_id for this digest.
				//
				// We deliberately only flip TO true here, never back to
				// false, so a transient verifier outage doesn't unwind
				// previously-good verifications. Admin can clear via SQL
				// if a key/identity rotation requires it.
				if v, method, vErr := parseCosignVerified(data); vErr == nil && v {
					now := time.Now().UTC()
					if err := tx.Exec(`
						UPDATE image_digests
						   SET verified_source = true,
						       verification_method = ?,
						       verified_at = ?
						 WHERE id = ?
					`, method, now, imageDigestID).Error; err != nil {
						log.Printf("image results: update verified_source failed: image_digest_id=%s err=%v", imageDigestID, err)
					}
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
	return extractOCILabel(raw, "org.opencontainers.image.source")
}

// extractRevisionLabel reads the OCI `image.revision` label — the git
// commit SHA the image claims to be built from. Persisted to
// sbom_bindings.commit_sha so the repo page can join commit → image.
// Empty when the label is missing or the JSON doesn't parse.
func extractRevisionLabel(raw []byte) string {
	return extractOCILabel(raw, "org.opencontainers.image.revision")
}

func extractOCILabel(raw []byte, key string) string {
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
	return strings.TrimSpace(config.Config.Labels[key])
}

// parseCosignVerified reads the JSON payload the image-scanner
// produces for the signature artifact (see runner/imagescan
// runSignature) and returns whether the verifier reported a
// successful identity match. Returns the verification_method
// alongside so the upload path can persist it on image_digests.
//
// Returns (false, "", err) when the JSON doesn't parse or doesn't
// carry the expected fields — caller treats that as "not verified"
// rather than aborting the whole upload.
func parseCosignVerified(data []byte) (bool, string, error) {
	var doc struct {
		Verified           bool   `json:"verified"`
		VerificationMethod string `json:"verification_method"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return false, "", err
	}
	if !doc.Verified {
		return false, "", nil
	}
	method := strings.TrimSpace(doc.VerificationMethod)
	if method == "" {
		method = "cosign"
	}
	return true, method, nil
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
