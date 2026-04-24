package runner

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/NorskHelsenett/spam/internal/artifacts"
	"github.com/NorskHelsenett/spam/internal/assets"
	"github.com/NorskHelsenett/spam/internal/jobs"
	"github.com/NorskHelsenett/spam/internal/manifests"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

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

	// Commit metadata captured by the runner via `git log -1` on the
	// pinned commit. Empty means older runner or capture failed — the
	// upsert tolerates missing fields by leaving them NULL.
	commitAuthorName := r.FormValue("commit_author_name")
	commitAuthorEmail := r.FormValue("commit_author_email")
	commitAuthorDateRaw := r.FormValue("commit_author_date")
	commitSigned := r.FormValue("commit_signed")
	commitMessage := r.FormValue("commit_message")
	var commitAuthorDate *time.Time
	if commitAuthorDateRaw != "" {
		if t, err := time.Parse(time.RFC3339, commitAuthorDateRaw); err == nil {
			commitAuthorDate = &t
		} else {
			log.Printf("run %s: unparseable commit_author_date %q: %v", runID, commitAuthorDateRaw, err)
		}
	}

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
	verifiedCommitSHA, verifyErr := verifyAndPersistRunCommit(r.Context(), s.db, payload, commitHash)
	if verifyErr != nil {
		log.Printf("run %s commit verification failed: %v", runID, verifyErr)
		http.Error(w, verifyErr.Error(), http.StatusConflict)
		return
	}

	sbomFile, _, err := r.FormFile("sbom")
	if err == nil {
		defer sbomFile.Close()
		sbomData, err := io.ReadAll(sbomFile)
		if err != nil {
			log.Printf("failed to read sbom: %v", err)
		} else {
			hash := sha256.Sum256(sbomData)

			var storedSBOMID string
			err := s.db.WithContext(r.Context()).Transaction(func(tx *gorm.DB) error {
				var binding *artifacts.BindingInput
				if payload.RepoID != "" && verifiedCommitSHA != "" {
					commit, err := assets.UpsertRepoCommit(r.Context(), tx, assets.RepoCommitInput{
						RepoID:      payload.RepoID,
						CommitSHA:   verifiedCommitSHA,
						Ref:         payload.Ref,
						AuthorName:  commitAuthorName,
						AuthorEmail: commitAuthorEmail,
						AuthorDate:  commitAuthorDate,
						Signed:      commitSigned,
						Message:     commitMessage,
					})
					if err != nil {
						log.Printf("failed to upsert repo commit: %v", err)
					} else {
						binding = &artifacts.BindingInput{
							AssetType:       artifacts.AssetTypeRepoCommit,
							AssetRefID:      commit.ID,
							CommitSHA:       verifiedCommitSHA,
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
			// Parse and store secrets findings, stripping absolute clone paths from File fields.
			secretsData = stripClonePaths(secretsData)
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
					if s.cache != nil && payload.RepoID != "" {
						_ = s.cache.Delete(r.Context(), "repo:metadata:"+payload.RepoID)
					}
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
	if verifiedCommitSHA != "" {
		if err := s.db.WithContext(r.Context()).Model(&Run{}).Where("id = ?", runID).Update("commit_hash", verifiedCommitSHA).Error; err != nil {
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

func verifyAndPersistRunCommit(ctx context.Context, db *gorm.DB, payload jobs.CreateRunPayload, observedCommitSHA string) (string, error) {
	observedCommitSHA = strings.TrimSpace(observedCommitSHA)
	expectedCommitSHA := strings.TrimSpace(payload.CommitSHA)
	commitSHA := observedCommitSHA
	if commitSHA == "" {
		commitSHA = expectedCommitSHA
	}

	if payload.RepoID == "" {
		return commitSHA, nil
	}
	if commitSHA == "" {
		return "", fmt.Errorf("missing commit hash for repo-linked run")
	}
	if expectedCommitSHA != "" && observedCommitSHA != "" && !strings.EqualFold(expectedCommitSHA, observedCommitSHA) {
		return "", fmt.Errorf("runner checked out %s but job expected %s", observedCommitSHA, expectedCommitSHA)
	}

	if _, err := assets.UpsertRepoCommit(ctx, db, assets.RepoCommitInput{
		RepoID:    payload.RepoID,
		CommitSHA: commitSHA,
		Ref:       payload.Ref,
	}); err != nil {
		return "", fmt.Errorf("persist repo commit: %w", err)
	}

	return commitSHA, nil
}

// stripClonePaths removes absolute clone directory prefixes from the "File"
// fields in gitleaks/betterleaks JSON output. The scanner runs inside a
// container where repos are cloned to paths like /work/<repo>, /tmp/scan/,
// etc. We want relative paths only.
func stripClonePaths(data []byte) []byte {
	var findings []map[string]interface{}
	if err := json.Unmarshal(data, &findings); err != nil {
		return data
	}

	changed := false
	for _, f := range findings {
		file, ok := f["File"].(string)
		if !ok || file == "" {
			continue
		}
		if !strings.HasPrefix(file, "/") {
			continue
		}
		// Strip everything up to and including the repo root directory.
		// Common patterns: /work/<anything>/, /tmp/<anything>/, /home/<anything>/
		// Strategy: find the first path component after known prefixes,
		// or strip up to the 3rd slash (e.g. /work/repo/ → rest).
		rel := file
		prefixes := []string{"/work/", "/tmp/", "/home/", "/src/", "/app/", "/repo/", "/scan/"}
		for _, prefix := range prefixes {
			if strings.HasPrefix(file, prefix) {
				rest := file[len(prefix):]
				// Skip the next path component (the repo dir itself)
				if idx := strings.Index(rest, "/"); idx >= 0 {
					rel = rest[idx+1:]
				} else {
					rel = rest
				}
				break
			}
		}
		// Fallback: if still absolute, strip up to 3rd /
		if strings.HasPrefix(rel, "/") {
			parts := strings.SplitN(rel, "/", 4)
			if len(parts) >= 4 {
				rel = parts[3]
			}
		}
		if rel != file {
			f["File"] = rel
			changed = true
		}
	}

	if !changed {
		return data
	}
	out, err := json.Marshal(findings)
	if err != nil {
		return data
	}
	return out
}
