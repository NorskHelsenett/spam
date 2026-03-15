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
	"github.com/NorskHelsenett/spam/internal/manifests"
	"github.com/NorskHelsenett/spam/internal/vulnerabilities"
	"github.com/NorskHelsenett/spam/internal/vulnmetrics"
	"gorm.io/gorm"
)

const maxTrivyResultBytes = 50 << 20 // 50 MB guard

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

func trivyScanNextHandler(db *gorm.DB) http.HandlerFunc {
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

// trivyManifestsHandler returns the latest manifest files for a repo so the
// scanner can fall back to filesystem scanning when the SBOM is a leaf.
func trivyManifestsHandler(db *gorm.DB) http.HandlerFunc {
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
			log.Printf("trivy/manifests: query repo %s: %v", repoID, err)
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
		if _, err := vulnmetrics.Refresh(r.Context(), db, time.Now().UTC()); err != nil {
			log.Printf("trivy/result: refresh dashboard metrics for %s: %v", sbomID, err)
		}

		w.WriteHeader(http.StatusNoContent)
	}
}
