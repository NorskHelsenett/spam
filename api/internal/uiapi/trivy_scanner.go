package uiapi

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/NorskHelsenett/spam/internal/vulnerabilities"
	"gorm.io/gorm"
)

const maxTrivyResultBytes = 50 << 20 // 50 MB guard

// TrivyScanNextHandler returns the next SBOM that needs Trivy scanning.
// 200 JSON with SBOMScanJob, 204 when the queue is empty.
//
// GET /api/trivy/next
func TrivyScanNextHandler(db *gorm.DB) http.HandlerFunc {
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
			log.Printf("trivy/next: get next sbom: %v", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if !ok {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		writeJSON(w, http.StatusOK, map[string]string{
			"sbom_id":   job.SBOMID,
			"repo_id":   job.RepoID,
			"format":    job.Format,
			"repo_slug": job.RepoSlug,
		})
	}
}

// TrivyScanResultHandler stores Trivy JSON scan output for a given SBOM.
//
// POST /api/trivy/result/{sbom_id}
func TrivyScanResultHandler(db *gorm.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sbomID := r.PathValue("sbom_id")
		if sbomID == "" {
			http.Error(w, "sbom_id required", http.StatusBadRequest)
			return
		}

		limited := io.LimitReader(r.Body, maxTrivyResultBytes+1)
		body, err := io.ReadAll(limited)
		if err != nil {
			http.Error(w, "failed to read body", http.StatusBadRequest)
			return
		}
		if int64(len(body)) > maxTrivyResultBytes {
			http.Error(w, "payload too large", http.StatusRequestEntityTooLarge)
			return
		}

		var report vulnerabilities.TrivyReport
		if err := json.Unmarshal(body, &report); err != nil {
			http.Error(w, "invalid trivy json: "+err.Error(), http.StatusBadRequest)
			return
		}

		// repo_id is passed as a query param from the scanner to avoid
		// needing a separate look-up inside StoreScanResult.
		repoID := r.URL.Query().Get("repo_id")

		if err := vulnerabilities.StoreScanResult(r.Context(), db, sbomID, repoID, report, json.RawMessage(body)); err != nil {
			log.Printf("trivy/result: store %s: %v", sbomID, err)
			http.Error(w, "failed to store result", http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusNoContent)
	}
}
