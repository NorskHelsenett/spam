package runner

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/NorskHelsenett/spam/internal/artifacts"
	"github.com/NorskHelsenett/spam/internal/jobs"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// TokenExchangeRequest is the request body for token exchange.
type TokenExchangeRequest struct {
	RunID string `json:"run_id"`
}

// TokenExchangeResponse is the response for token exchange.
type TokenExchangeResponse struct {
	Token string `json:"token"`
}

// handleTokenExchange exchanges a run token for a PAT.
// For now, this returns an empty token (public repos only).
// Future: look up stored PAT for private repo access.
func (s *Server) handleTokenExchange(w http.ResponseWriter, r *http.Request) {
	// Validate bearer token
	token := extractBearerToken(r)
	if token == "" {
		http.Error(w, "missing authorization", http.StatusUnauthorized)
		return
	}

	claims, err := ValidateRunToken(s.cfg.HMACKey, token)
	if err != nil {
		log.Printf("invalid token: %v", err)
		http.Error(w, "invalid token", http.StatusUnauthorized)
		return
	}

	// Parse request
	var req TokenExchangeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	// Verify run ID matches token
	if req.RunID != claims.RunID {
		http.Error(w, "run ID mismatch", http.StatusForbidden)
		return
	}

	// TODO: Look up PAT for the repository based on run payload
	// For now, return empty token (public repos only)
	resp := TokenExchangeResponse{
		Token: "", // Empty means public repo
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// handleResults receives SBOM and secrets results from a runner.
func (s *Server) handleResults(w http.ResponseWriter, r *http.Request) {
	// Validate bearer token
	token := extractBearerToken(r)
	if token == "" {
		http.Error(w, "missing authorization", http.StatusUnauthorized)
		return
	}

	claims, err := ValidateRunToken(s.cfg.HMACKey, token)
	if err != nil {
		log.Printf("invalid token: %v", err)
		http.Error(w, "invalid token", http.StatusUnauthorized)
		return
	}

	// Parse multipart form
	if err := r.ParseMultipartForm(100 << 20); err != nil { // 100MB max
		http.Error(w, "failed to parse form", http.StatusBadRequest)
		return
	}

	runID := r.FormValue("run_id")
	if runID != claims.RunID {
		http.Error(w, "run ID mismatch", http.StatusForbidden)
		return
	}

	// Get run to find repo_id
	var run Run
	if err := s.db.WithContext(r.Context()).Where("id = ?", runID).First(&run).Error; err != nil {
		log.Printf("failed to find run: %v", err)
		http.Error(w, "run not found", http.StatusNotFound)
		return
	}

	var payload CreateRunPayload
	if len(run.Payload) > 0 {
		json.Unmarshal(run.Payload, &payload)
	}

	// Process SBOM file
	sbomFile, _, err := r.FormFile("sbom")
	if err == nil {
		defer sbomFile.Close()
		sbomData, err := io.ReadAll(sbomFile)
		if err != nil {
			log.Printf("failed to read sbom: %v", err)
		} else {
			hash := sha256.Sum256(sbomData)

			var binding *artifacts.BindingInput
			if payload.RepoID != "" {
				binding = &artifacts.BindingInput{
					AssetType:       artifacts.AssetTypeRepoCommit,
					AssetRefID:      payload.RepoID,
					Source:          "spam-runner",
					CreatedByUserID: "system",
				}
			}

			err := s.db.WithContext(r.Context()).Transaction(func(tx *gorm.DB) error {
				sbomID, _, jobID, err := artifacts.StoreSBOMWithParseJob(
					r.Context(), tx,
					artifacts.SBOMInput{
						Format:           "cyclonedx-json",
						ContentHash:      hash[:],
						ContentBytes:     sbomData,
						IngestedByUserID: "system",
					},
					binding,
					func(ctx context.Context, tx *gorm.DB, sbomID, bindingID string) (string, error) {
						jobPayload := map[string]string{"sbom_id": sbomID}
						if bindingID != "" {
							jobPayload["binding_id"] = bindingID
						}
						job, err := jobs.CreateJobTx(ctx, tx, jobs.CreateJobInput{
							Type:    jobs.JobTypeParseSBOM,
							Payload: jobPayload,
						})
						if err != nil {
							return "", err
						}
						return job.ID, nil
					},
				)
				if err != nil {
					return err
				}
				log.Printf("ingested SBOM %s for run %s (%d bytes), job %s", sbomID, runID, len(sbomData), jobID)
				return nil
			})
			if err != nil {
				log.Printf("failed to ingest sbom: %v", err)
			}
		}
	}

	// Process secrets file
	secretsFile, _, err := r.FormFile("secrets")
	if err == nil {
		defer secretsFile.Close()
		secretsData, err := io.ReadAll(secretsFile)
		if err != nil {
			log.Printf("failed to read secrets: %v", err)
		} else {
			// Parse and store secrets findings
			var findings []interface{}
			if err := json.Unmarshal(secretsData, &findings); err != nil {
				log.Printf("failed to parse secrets: %v", err)
			} else {
				secret := RunSecret{
					ID:           uuid.New().String(),
					RunID:        runID,
					RepoID:       payload.RepoID,
					Findings:     secretsData,
					FindingCount: len(findings),
					CreatedAt:    time.Now(),
				}
				if err := s.db.WithContext(r.Context()).Create(&secret).Error; err != nil {
					log.Printf("failed to store secrets: %v", err)
				} else {
					log.Printf("stored %d secret findings for run %s", len(findings), runID)
				}
			}
		}
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"ok"}`))
}

func extractBearerToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if len(auth) > 7 && auth[:7] == "Bearer " {
		return auth[7:]
	}
	return ""
}
