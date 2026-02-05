package uiapi

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"strings"

	"github.com/NorskHelsenett/spam/internal/artifacts"
	"github.com/NorskHelsenett/spam/internal/assets"
	"github.com/NorskHelsenett/spam/internal/auth"
	"github.com/NorskHelsenett/spam/internal/events"
	"github.com/NorskHelsenett/spam/internal/jobs"
	"gorm.io/gorm"
)

const (
	maxSBOMUploadBytes = 25 << 20
	sbomSourceUpload   = "UPLOAD"
)

var (
	errRepoNotFound = errors.New("repo not found")
	errBadRequest   = errors.New("repo_id or org/slug required")
)

type sbomUploadResponse struct {
	SBOMID        string `json:"sbom_id"`
	BindingID     string `json:"binding_id"`
	RepoID        string `json:"repo_id"`
	RepoCommitID  string `json:"repo_commit_id"`
	ImageDigestID string `json:"image_digest_id"`
	JobID         string `json:"job_id"`
}

type sbomBoundPayload struct {
	SBOMID          string `json:"sbom_id"`
	BindingID       string `json:"binding_id"`
	AssetType       string `json:"asset_type"`
	RepoID          string `json:"repo_id"`
	RepoCommitID    string `json:"repo_commit_id"`
	CommitSHA       string `json:"commit_sha"`
	Provider        string `json:"provider"`
	Org             string `json:"org"`
	Slug            string `json:"slug"`
	ImageDigestID   string `json:"image_digest_id"`
	ImageRegistry   string `json:"image_registry"`
	ImageRepository string `json:"image_repository"`
	ImageDigest     string `json:"image_digest"`
	Source          string `json:"source"`
}

type sbomIngestedPayload struct {
	SBOMID string `json:"sbom_id"`
	Source string `json:"source"`
}

// SBOMUploadHandler accepts multipart SBOM uploads and enqueues parsing jobs.
func SBOMUploadHandler(db *gorm.DB, authService *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := requireAdmin(w, r, authService)
		if user == nil {
			return
		}

		if err := r.ParseMultipartForm(maxSBOMUploadBytes); err != nil {
			http.Error(w, "invalid multipart body", http.StatusBadRequest)
			return
		}

		file, _, err := r.FormFile("sbom_file")
		if err != nil {
			http.Error(w, "sbom_file required", http.StatusBadRequest)
			return
		}
		defer file.Close()

		limited := io.LimitReader(file, maxSBOMUploadBytes)
		content, err := io.ReadAll(limited)
		if err != nil {
			http.Error(w, "failed to read sbom file", http.StatusBadRequest)
			return
		}

		format := strings.TrimSpace(r.FormValue("format"))
		if format == "" {
			format = detectSBOMFormat(content)
		}
		if format == "" {
			http.Error(w, "unable to detect sbom format", http.StatusBadRequest)
			return
		}

		repoID := strings.TrimSpace(r.FormValue("repo_id"))
		provider := strings.TrimSpace(r.FormValue("provider"))
		org := strings.TrimSpace(r.FormValue("org"))
		slug := strings.TrimSpace(r.FormValue("slug"))
		commitSHA := strings.TrimSpace(r.FormValue("commit_sha"))
		ref := strings.TrimSpace(r.FormValue("ref"))
		imageRegistry := strings.TrimSpace(r.FormValue("image_registry"))
		imageRepository := strings.TrimSpace(r.FormValue("image_repository"))
		imageDigest := strings.TrimSpace(r.FormValue("image_digest"))

		repoProvided := repoID != "" || provider != "" || org != "" || slug != "" || commitSHA != "" || ref != ""
		imageProvided := imageRegistry != "" || imageRepository != "" || imageDigest != ""

		if repoProvided && imageProvided {
			http.Error(w, "choose repo or image target", http.StatusBadRequest)
			return
		}
		if repoProvided {
			if commitSHA == "" {
				http.Error(w, "commit_sha required for repo target", http.StatusBadRequest)
				return
			}
			if repoID == "" && (org == "" || slug == "") {
				http.Error(w, "repo_id or org/slug required for repo target", http.StatusBadRequest)
				return
			}
		}
		if imageProvided {
			if imageRegistry == "" || imageRepository == "" || imageDigest == "" {
				http.Error(w, "image_registry, image_repository, and image_digest required", http.StatusBadRequest)
				return
			}
		}

		hash := sha256.Sum256(content)

		var response sbomUploadResponse
		err = db.WithContext(r.Context()).Transaction(func(tx *gorm.DB) error {
			var bindingInput *artifacts.BindingInput
			var assetRefID string

			if repoProvided {
				repo, err := resolveRepo(r.Context(), tx, repoID, provider, org, slug, user.ID)
				if err != nil {
					return err
				}

				commit, err := assets.UpsertRepoCommit(r.Context(), tx, assets.RepoCommitInput{
					RepoID:    repo.ID,
					CommitSHA: commitSHA,
					Ref:       ref,
				})
				if err != nil {
					return err
				}

				bindingInput = &artifacts.BindingInput{
					AssetType:       artifacts.AssetTypeRepoCommit,
					AssetRefID:      commit.ID,
					Source:          sbomSourceUpload,
					CreatedByUserID: user.ID,
				}
				assetRefID = commit.ID
				response.RepoID = repo.ID
				response.RepoCommitID = commit.ID
			}

			if imageProvided {
				image, err := assets.UpsertImageDigest(r.Context(), tx, assets.ImageDigestInput{
					Registry:        imageRegistry,
					Repository:      imageRepository,
					Digest:          imageDigest,
					CreatedByUserID: user.ID,
				})
				if err != nil {
					return err
				}

				bindingInput = &artifacts.BindingInput{
					AssetType:       artifacts.AssetTypeImageDigest,
					AssetRefID:      image.ID,
					Source:          sbomSourceUpload,
					CreatedByUserID: user.ID,
				}
				assetRefID = image.ID
				response.ImageDigestID = image.ID
			}

			sbomID, bindingID, jobID, err := artifacts.StoreSBOMWithParseJob(
				r.Context(), tx,
				artifacts.SBOMInput{
					Format:           format,
					ContentHash:      hash[:],
					ContentBytes:     content,
					IngestedByUserID: user.ID,
				},
				bindingInput,
				func(ctx context.Context, tx *gorm.DB, sbomID, bindingID string) (string, error) {
					payload := map[string]string{"sbom_id": sbomID}
					if bindingID != "" {
						payload["binding_id"] = bindingID
					}
					job, err := jobs.CreateJobTx(ctx, tx, jobs.CreateJobInput{
						Type:    jobs.JobTypeParseSBOM,
						Payload: payload,
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

			response.SBOMID = sbomID
			response.JobID = jobID
			if bindingID != "" {
				response.BindingID = bindingID
			}

			// Emit appropriate events
			if bindingInput != nil {
				if repoProvided {
					repo, _ := resolveRepo(r.Context(), tx, repoID, provider, org, slug, user.ID)
					commit, _ := assets.FindRepoCommit(r.Context(), tx, assetRefID)
					if err := events.EmitSBOMBound(tx, sbomID, sbomBoundPayload{
						SBOMID:       sbomID,
						BindingID:    bindingID,
						AssetType:    artifacts.AssetTypeRepoCommit,
						RepoID:       repo.ID,
						RepoCommitID: commit.ID,
						CommitSHA:    commit.CommitSHA,
						Provider:     repo.Provider,
						Org:          repo.Org,
						Slug:         repo.Slug,
						Source:       sbomSourceUpload,
					}); err != nil {
						return err
					}
				}
				if imageProvided {
					image, _ := assets.FindImageDigest(r.Context(), tx, assetRefID)
					if err := events.EmitSBOMBound(tx, sbomID, sbomBoundPayload{
						SBOMID:          sbomID,
						BindingID:       bindingID,
						AssetType:       artifacts.AssetTypeImageDigest,
						ImageDigestID:   image.ID,
						ImageRegistry:   image.Registry,
						ImageRepository: image.Repository,
						ImageDigest:     image.Digest,
						Source:          sbomSourceUpload,
					}); err != nil {
						return err
					}
				}
			} else {
				if err := events.EmitSBOMIngested(tx, sbomID, sbomIngestedPayload{
					SBOMID: sbomID,
					Source: sbomSourceUpload,
				}); err != nil {
					return err
				}
			}

			return nil
		})
		if err != nil {
			if errors.Is(err, errRepoNotFound) {
				http.Error(w, "repo not found", http.StatusNotFound)
				return
			}
			if errors.Is(err, errBadRequest) {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if errors.Is(err, artifacts.ErrBindingExists) {
				http.Error(w, "sbom already exists for this commit", http.StatusConflict)
				return
			}
			log.Printf("SBOM upload failed (repo_id=%q provider=%q org=%q slug=%q image_registry=%q image_repository=%q image_digest=%q): %v", repoID, provider, org, slug, imageRegistry, imageRepository, imageDigest, err)
			http.Error(w, "sbom upload failed", http.StatusInternalServerError)
			return
		}

		if _, err := jobs.CreateJob(r.Context(), db, jobs.CreateJobInput{
			Type:    jobs.JobTypeRefreshSBOMViews,
			Payload: map[string]string{"sbom_id": response.SBOMID},
		}); err != nil {
			log.Printf("failed to enqueue view refresh: %v", err)
		}

		writeJSON(w, http.StatusCreated, response)
	}
}

func resolveRepo(ctx context.Context, tx *gorm.DB, repoID, provider, org, slug, createdBy string) (*assets.Repo, error) {
	if org != "" && slug != "" {
		return assets.UpsertRepo(ctx, tx, assets.RepoInput{
			Provider:        provider,
			Org:             org,
			Slug:            slug,
			CreatedByUserID: createdBy,
		})
	}

	if repoID != "" {
		var repo assets.Repo
		if err := tx.WithContext(ctx).First(&repo, "id = ?", repoID).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return nil, errRepoNotFound
			}
			return nil, err
		}
		return &repo, nil
	}

	return nil, errBadRequest
}

func detectSBOMFormat(payload []byte) string {
	var decoded map[string]interface{}
	if err := json.Unmarshal(payload, &decoded); err != nil {
		return ""
	}

	if value, ok := decoded["bomFormat"].(string); ok && strings.EqualFold(value, "CycloneDX") {
		return "cyclonedx-json"
	}
	if _, ok := decoded["spdxVersion"].(string); ok {
		return "spdx-json"
	}

	return ""
}

// SBOMDownloadHandler downloads an SBOM by ID.
// GET /api/sboms/{id}/download
func SBOMDownloadHandler(db *gorm.DB, authService *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if requireAuth(w, r, authService) == nil {
			return
		}

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
		w.Write(sbom.ContentBytes)
	}
}

// SBOMGetHandler returns SBOM metadata by ID.
// GET /api/sboms/{id}
func SBOMGetHandler(db *gorm.DB, authService *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if requireAuth(w, r, authService) == nil {
			return
		}

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

		// Count components linked to this SBOM
		var componentCount int64
		if err := db.WithContext(r.Context()).
			Table("sbom_components").
			Where("sbom_id = ?", sbomID).
			Count(&componentCount).Error; err != nil {
			log.Printf("failed to count sbom components: %v", err)
			componentCount = 0
		}

		writeJSON(w, http.StatusOK, map[string]interface{}{
			"id":              sbom.ID,
			"format":          sbom.Format,
			"created_at":      sbom.CreatedAt,
			"component_count": componentCount,
		})
	}
}

func writeJSON(w http.ResponseWriter, status int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}
