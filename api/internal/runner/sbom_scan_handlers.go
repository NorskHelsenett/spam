package runner

import (
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/NorskHelsenett/spam/internal/artifacts"
	"github.com/NorskHelsenett/spam/internal/assetrisk"
	"github.com/NorskHelsenett/spam/internal/imagescan"
	"github.com/NorskHelsenett/spam/internal/jobs"
	"github.com/NorskHelsenett/spam/internal/manifests"
	"github.com/NorskHelsenett/spam/internal/vulnerabilities"
	"github.com/NorskHelsenett/spam/internal/vulnmetrics"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

const maxScanResultBytes = 50 << 20 // 50 MB guard

func sbomDownloadHandler(db *gorm.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sbomID := r.PathValue("id")
		if sbomID == "" {
			http.Error(w, "sbom ID required", http.StatusBadRequest)
			return
		}

		sbom, err := artifacts.FindSBOM(r.Context(), db, sbomID)
		if err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				http.Error(w, "sbom not found", http.StatusNotFound)
				return
			}
			http.Error(w, "failed to fetch sbom", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", "attachment; filename=sbom.json")
		_, _ = w.Write(sbom.ContentBytes)
	}
}

func sbomScanNextHandler(db *gorm.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		leasedBy, _ := os.Hostname()
		runStartedAt := time.Now().UTC()
		if raw := r.URL.Query().Get("run_started_at"); raw != "" {
			parsed, err := time.Parse(time.RFC3339, raw)
			if err != nil {
				http.Error(w, "invalid run_started_at", http.StatusBadRequest)
				return
			}
			runStartedAt = parsed.UTC()
		}

		job, ok, err := vulnerabilities.GetNextSBOMToScan(r.Context(), db, leasedBy, runStartedAt)
		if err != nil {
			log.Printf("sbom-scan/next: get next sbom: %v", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if !ok {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"sbom_id":      job.SBOMID,
			"repo_id":      job.RepoID,
			"format":       job.Format,
			"repo_slug":    job.RepoSlug,
			"asset_type":   job.AssetType,
			"asset_ref_id": job.AssetRefID,
		})
	}
}

// sbomScanManifestsHandler returns the latest manifest files for a repo so the
// scanner can fall back to filesystem scanning when the SBOM is a leaf.
func sbomScanManifestsHandler(db *gorm.DB) http.HandlerFunc {
	type manifestFile struct {
		Path    string `json:"path"`
		Content string `json:"content"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		repoID := r.PathValue("repo_id")
		if repoID == "" {
			http.Error(w, "repo_id required", http.StatusBadRequest)
			return
		}

		// Latest version of each distinct path for this repo.
		var rows []manifests.Manifest
		if err := db.WithContext(r.Context()).
			Raw(`SELECT DISTINCT ON (path) path, content
			     FROM manifests
			     WHERE repo_id = ?
			     ORDER BY path, created_at DESC`, repoID).
			Scan(&rows).Error; err != nil {
			log.Printf("sbom-scan/manifests: query repo %s: %v", repoID, err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		out := make([]manifestFile, 0, len(rows))
		for _, m := range rows {
			out = append(out, manifestFile{Path: m.Path, Content: m.Content})
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	}
}

// grypeImageResultHandler ingests a grype JSON scan result for an
// IMAGE_DIGEST-bound SBOM. The sbom-scanner posts here when it ran grype
// against a stored image SBOM (no image pull) to refresh findings against
// a newer grype DB.
//
// Flow:
//  1. Resolve image_digest_id from sbom_bindings (must be IMAGE_DIGEST).
//  2. Create a new image_scan_runs row (scan_type inferred from presence
//     of an sbom-revuln marker — just a normal run for now).
//  3. Parse grype JSON via imagescan.ParseAndStoreGrype → image_vuln_findings.
//  4. Release the sbom_scan_leases row so the next-SBOM query can advance.
//
// POST /api/sbom-scan/image-result/{sbom_id}
func grypeImageResultHandler(db *gorm.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sbomID := r.PathValue("sbom_id")
		if sbomID == "" {
			http.Error(w, "sbom_id required", http.StatusBadRequest)
			return
		}

		limited := io.LimitReader(r.Body, maxScanResultBytes+1)
		body, err := io.ReadAll(limited)
		if err != nil {
			http.Error(w, "failed to read body", http.StatusBadRequest)
			return
		}
		if int64(len(body)) > maxScanResultBytes {
			http.Error(w, "payload too large", http.StatusRequestEntityTooLarge)
			return
		}

		// Resolve image digest from the binding.
		var binding struct {
			AssetRefID string `gorm:"column:asset_ref_id"`
			AssetType  string `gorm:"column:asset_type"`
		}
		err = db.WithContext(r.Context()).Raw(
			`SELECT asset_ref_id, asset_type FROM sbom_bindings WHERE sbom_id = ? AND asset_type = 'IMAGE_DIGEST' LIMIT 1`,
			sbomID,
		).Scan(&binding).Error
		if err != nil {
			log.Printf("grype/image-result: lookup binding %s: %v", sbomID, err)
			http.Error(w, "failed to resolve sbom binding", http.StatusInternalServerError)
			return
		}
		if binding.AssetRefID == "" {
			http.Error(w, "sbom is not bound to an image", http.StatusBadRequest)
			return
		}

		now := time.Now().UTC()
		scanRunID := uuid.NewString()
		err = db.WithContext(r.Context()).Transaction(func(tx *gorm.DB) error {
			// Insert a run row. finished_at is set immediately since this
			// is a synchronous SBOM revuln (no separate complete step).
			run := imagescan.ImageScanRun{
				ID:            scanRunID,
				ImageDigestID: binding.AssetRefID,
				StartedAt:     &now,
				FinishedAt:    &now,
				CreatedAt:     now,
			}
			if err := tx.Create(&run).Error; err != nil {
				return err
			}
			if _, err := imagescan.ParseAndStoreGrype(r.Context(), tx, binding.AssetRefID, scanRunID, body); err != nil {
				return err
			}
			// Release the lease so the next-SBOM query can pick up the next one.
			if err := tx.Exec(`DELETE FROM sbom_scan_leases WHERE sbom_id = ?`, sbomID).Error; err != nil {
				return err
			}
			return nil
		})
		if err != nil {
			log.Printf("grype/image-result: store %s: %v", sbomID, err)
			http.Error(w, "failed to store result", http.StatusInternalServerError)
			return
		}

		// Same story as sbomScanResultHandler: fresh vuln rows just
		// landed, warm the dashboard cache before an operator hits
		// the list page.
		vulnmetrics.TriggerRefresh(db)
		assetrisk.TriggerRefresh(db)
		jobs.EnqueueMissingVulnMeta(r.Context(), db)

		w.WriteHeader(http.StatusNoContent)
	}
}

// sbomScanResultHandler ingests a grype JSON scan result for a
// REPO_COMMIT-bound SBOM. The sbom-scanner posts here after running
// grype against the stored SBOM; raw_json is persisted as-is so
// advanced_search can introspect individual matches.
func sbomScanResultHandler(db *gorm.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sbomID := r.PathValue("sbom_id")
		if sbomID == "" {
			http.Error(w, "sbom_id required", http.StatusBadRequest)
			return
		}

		limited := io.LimitReader(r.Body, maxScanResultBytes+1)
		body, err := io.ReadAll(limited)
		if err != nil {
			http.Error(w, "failed to read body", http.StatusBadRequest)
			return
		}
		if int64(len(body)) > maxScanResultBytes {
			http.Error(w, "payload too large", http.StatusRequestEntityTooLarge)
			return
		}

		repoID := r.URL.Query().Get("repo_id")

		var report vulnerabilities.GrypeReport
		if err := json.Unmarshal(body, &report); err != nil {
			http.Error(w, "invalid grype json: "+err.Error(), http.StatusBadRequest)
			return
		}
		if err := vulnerabilities.StoreScanResult(r.Context(), db, sbomID, repoID, report, json.RawMessage(body)); err != nil {
			log.Printf("sbom-scan/result: store %s: %v", sbomID, err)
			http.Error(w, "failed to store result", http.StatusInternalServerError)
			return
		}

		// Warm the dashboard cache in the background so the next
		// operator page load hits a ready result instead of paying
		// the recompute cost on the UI thread. Coalesced so a batch
		// of completions produces at most one refresh + one follow-up.
		vulnmetrics.TriggerRefresh(db)
		assetrisk.TriggerRefresh(db)
		jobs.EnqueueMissingVulnMeta(r.Context(), db)

		w.WriteHeader(http.StatusNoContent)
	}
}
