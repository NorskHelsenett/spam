package runner

import (
	"crypto/sha256"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/NorskHelsenett/spam/internal/artifacts"
	"github.com/NorskHelsenett/spam/internal/assets"
	"github.com/NorskHelsenett/spam/internal/jobs"
	"github.com/NorskHelsenett/spam/internal/manifests"
	"github.com/NorskHelsenett/spam/internal/providerconfig"
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

	// Load run payload for provider metadata
	var run Run
	if err := s.db.WithContext(r.Context()).Where("id = ?", req.RunID).First(&run).Error; err != nil {
		http.Error(w, "run not found", http.StatusNotFound)
		return
	}

	var payload jobs.CreateRunPayload
	if len(run.Payload) > 0 {
		if err := json.Unmarshal(run.Payload, &payload); err != nil {
			log.Printf("failed to unmarshal run payload: %v", err)
			http.Error(w, "invalid run payload", http.StatusInternalServerError)
			return
		}
	}

	providerToken := ""
	if payload.ProviderID != "" {
		pat, err := providerconfig.GetActiveToken(r.Context(), s.db, payload.ProviderID, s.cfg.ProviderSecretsKey)
		if err != nil {
			log.Printf("token exchange failed: %v", err)
			http.Error(w, "failed to load provider token", http.StatusInternalServerError)
			return
		}
		providerToken = pat
	}

	resp := TokenExchangeResponse{
		Token: providerToken,
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

	// Get commit_hash if provided
	commitHash := r.FormValue("commit_hash")

	// Get run to find repo_id
	var run Run
	if err := s.db.WithContext(r.Context()).Where("id = ?", runID).First(&run).Error; err != nil {
		log.Printf("failed to find run: %v", err)
		http.Error(w, "run not found", http.StatusNotFound)
		return
	}

	var payload jobs.CreateRunPayload
	if len(run.Payload) > 0 {
		if err := json.Unmarshal(run.Payload, &payload); err != nil {
			log.Printf("failed to unmarshal run payload: %v", err)
		}
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

			commitSHA := commitHash
			if commitSHA == "" {
				commitSHA = payload.CommitSHA
			}

			var storedSBOMID string
			err := s.db.WithContext(r.Context()).Transaction(func(tx *gorm.DB) error {
				var binding *artifacts.BindingInput
				if payload.RepoID != "" && commitSHA != "" {
					commit, err := assets.UpsertRepoCommit(r.Context(), tx, assets.RepoCommitInput{
						RepoID:    payload.RepoID,
						CommitSHA: commitSHA,
						Ref:       payload.Ref,
					})
					if err != nil {
						log.Printf("failed to upsert repo commit: %v", err)
					} else {
						binding = &artifacts.BindingInput{
							AssetType:       artifacts.AssetTypeRepoCommit,
							AssetRefID:      commit.ID,
							CommitSHA:       commitSHA,
							Source:          "spam-runner",
							CreatedByUserID: "system",
						}
					}
				}

				sbomID, _, err := artifacts.StoreSBOM(
					r.Context(), tx,
					artifacts.SBOMInput{
						Format:           "cyclonedx-json",
						ContentHash:      hash[:],
						ContentBytes:     sbomData,
						IngestedByUserID: "system",
					},
					binding,
				)
				if err != nil {
					return err
				}
				storedSBOMID = sbomID
				log.Printf("ingested SBOM %s for run %s (%d bytes)", sbomID, runID, len(sbomData))
				return nil
			})
			if err != nil {
				log.Printf("failed to ingest sbom: %v", err)
			} else if storedSBOMID != "" {
				if _, err := jobs.CreateJob(r.Context(), s.db, jobs.CreateJobInput{
					Type:    jobs.JobTypeRefreshSBOMViews,
					Payload: map[string]string{"sbom_id": storedSBOMID},
				}); err != nil {
					log.Printf("failed to enqueue view refresh: %v", err)
				}
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

	// Process manifests file
	manifestsFile, _, err := r.FormFile("manifests")
	if err == nil {
		defer manifestsFile.Close()
		manifestsData, err := io.ReadAll(manifestsFile)
		if err != nil {
			log.Printf("failed to read manifests: %v", err)
		} else {
			// Parse and store manifests
			manifests, deps, err := manifests.ParseManifests(runID, payload.RepoID, manifestsData)
			if err != nil {
				log.Printf("failed to parse manifests: %v", err)
			} else if len(manifests) > 0 {
				if err := s.db.WithContext(r.Context()).Create(&manifests).Error; err != nil {
					log.Printf("failed to store manifests: %v", err)
				} else {
					log.Printf("stored %d manifest files for run %s", len(manifests), runID)

					// Store dependencies
					if len(deps) > 0 {
						if err := s.db.WithContext(r.Context()).Create(&deps).Error; err != nil {
							log.Printf("failed to store manifest dependencies: %v", err)
						} else {
							log.Printf("stored %d dependencies from manifests", len(deps))
						}
					}
				}
			}
		}
	}

	// Update run with commit hash if provided
	if commitHash != "" {
		if err := s.db.WithContext(r.Context()).Model(&Run{}).Where("id = ?", runID).Update("commit_hash", commitHash).Error; err != nil {
			log.Printf("failed to update commit hash: %v", err)
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
