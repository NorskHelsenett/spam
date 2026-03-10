package runner

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"

	"github.com/NorskHelsenett/spam/internal/vulnerabilities"
	"gorm.io/gorm"
)

const maxTrivyResultBytes = 50 << 20 // 50 MB guard

func trivyScanNextHandler(db *gorm.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		leasedBy, _ := os.Hostname()

		job, ok, err := vulnerabilities.GetNextSBOMToScan(r.Context(), db, leasedBy)
		if err != nil {
			log.Printf("trivy/next: get next sbom: %v", err)
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
			"sbom_id":   job.SBOMID,
			"repo_id":   job.RepoID,
			"format":    job.Format,
			"repo_slug": job.RepoSlug,
		})
	}
}

func trivyScanResultHandler(db *gorm.DB) http.HandlerFunc {
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

		repoID := r.URL.Query().Get("repo_id")
		if err := vulnerabilities.StoreScanResult(r.Context(), db, sbomID, repoID, report, json.RawMessage(body)); err != nil {
			log.Printf("trivy/result: store %s: %v", sbomID, err)
			http.Error(w, "failed to store result", http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusNoContent)
	}
}
