package uiapi

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/NorskHelsenett/spam/internal/auth"
	"github.com/NorskHelsenett/spam/internal/jobs"
	"github.com/NorskHelsenett/spam/internal/runner"
	"gorm.io/gorm"
)

// RunStreamHandler streams logs for a run via SSE.
// GET /api/runs/{id}/stream
func RunStreamHandler(db *gorm.DB, authService *auth.Service, k8sClient *runner.K8sClient) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if requireAuth(w, r, authService) == nil {
			return
		}

		runID := r.PathValue("id")
		if runID == "" {
			http.Error(w, "missing run ID", http.StatusBadRequest)
			return
		}

		// Get the run to check it exists
		var run runner.Run
		if err := db.WithContext(r.Context()).Where("id = ?", runID).First(&run).Error; err != nil {
			if err == gorm.ErrRecordNotFound {
				http.Error(w, "run not found", http.StatusNotFound)
				return
			}
			http.Error(w, "failed to get run", http.StatusInternalServerError)
			return
		}

		// Set SSE headers
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		w.Header().Set("X-Accel-Buffering", "no")

		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "streaming unsupported", http.StatusInternalServerError)
			return
		}

		// Get last_id parameter for resuming
		lastID, _ := strconv.ParseInt(r.URL.Query().Get("last_id"), 10, 64)

		// Helper to send K8s event snapshot (if available)
		// Returns (failed, errorMsg) if a K8s error was detected and status was updated
		sendK8sSnapshot := func() (bool, string) {
			var (
				events    []runner.K8sEvent
				podStatus *runner.PodStatus
				err       error
			)

			if k8sClient != nil && run.K8sJobName != "" && run.K8sNamespace != "" {
				events, err = k8sClient.GetJobEvents(r.Context(), run.K8sJobName, run.K8sNamespace)
				if err != nil {
					log.Printf("failed to get job events: %v", err)
				} else {
					podStatus, _ = k8sClient.GetPodStatus(r.Context(), run.K8sJobName, run.K8sNamespace)
					if err := persistK8sSnapshot(r.Context(), db, runID, events, podStatus); err != nil {
						log.Printf("failed to store events: %v", err)
					}
				}
			}

			if len(events) == 0 && podStatus == nil {
				var ok bool
				events, podStatus, ok, err = loadPersistedK8sSnapshot(r.Context(), db, runID)
				if err != nil {
					log.Printf("failed to load stored events: %v", err)
					return false, ""
				}
				if !ok {
					return false, ""
				}
			}

			payload := map[string]interface{}{
				"events":     events,
				"pod_status": podStatus,
			}
			data, _ := json.Marshal(payload)
			fmt.Fprintf(w, "event: k8s\n")
			fmt.Fprintf(w, "data: %s\n\n", data)
			flusher.Flush()

			// Check if K8s reported an error and update run status if needed
			newStatus, errorMsg, updated := correctRunStatusFromSnapshot(r.Context(), db, runID, string(run.Status), events, podStatus)
			if updated && newStatus == "FAILED" {
				run.Status = runner.RunStatus(newStatus)
				return true, errorMsg
			}
			return false, ""
		}

		// Send historical logs
		var logs []runner.RunLog
		query := db.WithContext(r.Context()).Where("run_id = ?", runID)
		if lastID > 0 {
			query = query.Where("id > ?", lastID)
		}
		if err := query.Order("id ASC").Find(&logs).Error; err != nil {
			log.Printf("failed to fetch logs: %v", err)
		}

		for _, logEntry := range logs {
			event := map[string]interface{}{
				"line": logEntry.Line,
				"ts":   logEntry.CreatedAt.Format("2006-01-02T15:04:05Z"),
			}
			data, _ := json.Marshal(event)
			fmt.Fprintf(w, "id: %d\n", logEntry.ID)
			fmt.Fprintf(w, "event: log\n")
			fmt.Fprintf(w, "data: %s\n\n", data)
		}
		flusher.Flush()

		// Send initial K8s snapshot (if any) and check for K8s errors
		if k8sFailed, k8sError := sendK8sSnapshot(); k8sFailed {
			// K8s error detected (e.g., ImagePullBackOff), send failure status and close
			statusEvent := map[string]interface{}{
				"status": "FAILED",
				"error":  k8sError,
			}
			data, _ := json.Marshal(statusEvent)
			fmt.Fprintf(w, "event: status\n")
			fmt.Fprintf(w, "data: %s\n\n", data)
			flusher.Flush()
			return
		}

		// If run is already complete, send status and close
		if run.Status == runner.RunStatusSucceeded || run.Status == runner.RunStatusFailed || run.Status == runner.RunStatusCancelled {
			statusEvent := map[string]interface{}{
				"status":      string(run.Status),
				"commit_hash": run.CommitHash,
			}

			// Parse payload to get repo_id for SBOM lookup
			var payload jobs.CreateRunPayload
			if len(run.Payload) > 0 {
				json.Unmarshal(run.Payload, &payload)
			}

			// Look up associated SBOM via repo commit
			if payload.RepoID != "" && run.CommitHash != "" {
				var repoCommit struct{ ID string }
				if err := db.WithContext(r.Context()).Table("repo_commits").
					Where("repo_id = ? AND commit_sha = ?", payload.RepoID, run.CommitHash).
					Select("id").First(&repoCommit).Error; err == nil {
					var sbomBinding struct{ SBOMID string }
					if err := db.WithContext(r.Context()).Table("sbom_bindings").
						Where("asset_type = ? AND asset_ref_id = ?", "REPO_COMMIT", repoCommit.ID).
						Select("sbom_id").First(&sbomBinding).Error; err == nil {
						statusEvent["sbom_id"] = sbomBinding.SBOMID
					}
				}
			}

			// Look up associated secrets
			var secret struct{ ID string }
			if err := db.WithContext(r.Context()).Table("run_secrets").
				Where("run_id = ?", runID).
				Select("id").First(&secret).Error; err == nil {
				statusEvent["secret_id"] = secret.ID
			}

			// Count manifests
			var manifestCount int64
			if err := db.WithContext(r.Context()).Table("manifests").
				Where("run_id = ?", runID).
				Count(&manifestCount).Error; err == nil {
				statusEvent["manifest_count"] = manifestCount
			}

			data, _ := json.Marshal(statusEvent)
			fmt.Fprintf(w, "event: status\n")
			fmt.Fprintf(w, "data: %s\n\n", data)
			flusher.Flush()
			return
		}

		// For running jobs, poll for new logs every 2 seconds
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()

		var k8sTicker *time.Ticker
		var k8sTick <-chan time.Time
		if k8sClient != nil && run.K8sJobName != "" && run.K8sNamespace != "" {
			k8sTicker = time.NewTicker(5 * time.Second)
			defer k8sTicker.Stop()
			k8sTick = k8sTicker.C
		}

		var lastLogID int64
		if len(logs) > 0 {
			lastLogID = logs[len(logs)-1].ID
		}

		for {
			select {
			case <-r.Context().Done():
				return
			case <-ticker.C:
				// Fetch new logs
				var newLogs []runner.RunLog
				if err := db.WithContext(r.Context()).
					Where("run_id = ? AND id > ?", runID, lastLogID).
					Order("id ASC").
					Find(&newLogs).Error; err != nil {
					log.Printf("failed to fetch new logs: %v", err)
					continue
				}

				// Send new logs
				for _, logEntry := range newLogs {
					event := map[string]interface{}{
						"line": logEntry.Line,
						"ts":   logEntry.CreatedAt.Format("2006-01-02T15:04:05Z"),
					}
					data, _ := json.Marshal(event)
					fmt.Fprintf(w, "id: %d\n", logEntry.ID)
					fmt.Fprintf(w, "event: log\n")
					fmt.Fprintf(w, "data: %s\n\n", data)
					lastLogID = logEntry.ID
				}
				if len(newLogs) > 0 {
					flusher.Flush()
				}

				// Check if run completed
				if err := db.WithContext(r.Context()).Where("id = ?", runID).First(&run).Error; err == nil {
					if run.Status == runner.RunStatusSucceeded || run.Status == runner.RunStatusFailed || run.Status == runner.RunStatusCancelled {
						// Send final K8s snapshot before closing
						_, _ = sendK8sSnapshot()

						// Send final status
						statusEvent := map[string]interface{}{
							"status":      string(run.Status),
							"commit_hash": run.CommitHash,
						}

						// Parse payload to get repo_id for SBOM lookup
						var payload jobs.CreateRunPayload
						if len(run.Payload) > 0 {
							json.Unmarshal(run.Payload, &payload)
						}

						// Look up associated SBOM via repo commit
						if payload.RepoID != "" && run.CommitHash != "" {
							var repoCommit struct{ ID string }
							if err := db.WithContext(r.Context()).Table("repo_commits").
								Where("repo_id = ? AND commit_sha = ?", payload.RepoID, run.CommitHash).
								Select("id").First(&repoCommit).Error; err == nil {
								var sbomBinding struct{ SBOMID string }
								if err := db.WithContext(r.Context()).Table("sbom_bindings").
									Where("asset_type = ? AND asset_ref_id = ?", "REPO_COMMIT", repoCommit.ID).
									Select("sbom_id").First(&sbomBinding).Error; err == nil {
									statusEvent["sbom_id"] = sbomBinding.SBOMID
								}
							}
						}

						var secret struct{ ID string }
						if err := db.WithContext(r.Context()).Table("run_secrets").
							Where("run_id = ?", runID).
							Select("id").First(&secret).Error; err == nil {
							statusEvent["secret_id"] = secret.ID
						}

						// Count manifests
						var manifestCount int64
						if err := db.WithContext(r.Context()).Table("manifests").
							Where("run_id = ?", runID).
							Count(&manifestCount).Error; err == nil {
							statusEvent["manifest_count"] = manifestCount
						}

						data, _ := json.Marshal(statusEvent)
						fmt.Fprintf(w, "event: status\n")
						fmt.Fprintf(w, "data: %s\n\n", data)
						flusher.Flush()
						return
					}
				}
			case <-k8sTick:
				// Check for K8s errors during polling
				if k8sFailed, k8sError := sendK8sSnapshot(); k8sFailed {
					// K8s error detected (e.g., ImagePullBackOff), send failure status and close
					statusEvent := map[string]interface{}{
						"status": "FAILED",
						"error":  k8sError,
					}
					data, _ := json.Marshal(statusEvent)
					fmt.Fprintf(w, "event: status\n")
					fmt.Fprintf(w, "data: %s\n\n", data)
					flusher.Flush()
					return
				}
			}
		}
	}
}
