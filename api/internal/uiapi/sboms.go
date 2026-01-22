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
	maxSBOMUploadBytes  = 25 << 20
	assetTypeRepoCommit = "REPO_COMMIT"
	sbomSourceUpload    = "UPLOAD"
)

var (
	errRepoNotFound = errors.New("repo not found")
	errBadRequest   = errors.New("repo_id or org/slug required")
)

type sbomUploadResponse struct {
	SBOMID       string `json:"sbom_id"`
	BindingID    string `json:"binding_id"`
	RepoID       string `json:"repo_id"`
	RepoCommitID string `json:"repo_commit_id"`
	JobID        string `json:"job_id"`
}

type sbomBoundPayload struct {
	SBOMID       string `json:"sbom_id"`
	RepoID       string `json:"repo_id"`
	RepoCommitID string `json:"repo_commit_id"`
	CommitSHA    string `json:"commit_sha"`
	Provider     string `json:"provider"`
	Org          string `json:"org"`
	Slug         string `json:"slug"`
	Source       string `json:"source"`
}

// SBOMUploadHandler accepts multipart SBOM uploads and enqueues parsing jobs.
func SBOMUploadHandler(db *gorm.DB, authService *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if authService == nil {
			http.Error(w, "auth unavailable", http.StatusInternalServerError)
			return
		}

		session, err := authService.LoadSession(r)
		if err != nil {
			http.Error(w, "unauthenticated", http.StatusUnauthorized)
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
		if commitSHA == "" {
			http.Error(w, "commit_sha required", http.StatusBadRequest)
			return
		}

		if repoID == "" && (org == "" || slug == "") {
			http.Error(w, "repo_id or org/slug required", http.StatusBadRequest)
			return
		}

		hash := sha256.Sum256(content)

		var response sbomUploadResponse
		err = db.WithContext(r.Context()).Transaction(func(tx *gorm.DB) error {
			repo, err := resolveRepo(r.Context(), tx, repoID, provider, org, slug, session.UserID)
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

			sbom, err := artifacts.UpsertSBOM(r.Context(), tx, artifacts.SBOMInput{
				Format:           format,
				ContentHash:      hash[:],
				ContentBytes:     content,
				IngestedByUserID: session.UserID,
			})
			if err != nil {
				return err
			}

			binding, err := artifacts.UpsertBinding(r.Context(), tx, artifacts.BindingInput{
				AssetType:       assetTypeRepoCommit,
				AssetRefID:      commit.ID,
				SBOMID:          sbom.ID,
				Source:          sbomSourceUpload,
				CreatedByUserID: session.UserID,
			})
			if err != nil {
				return err
			}

			if err := events.EmitSBOMBound(tx, sbom.ID, sbomBoundPayload{
				SBOMID:       sbom.ID,
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

			job, err := jobs.CreateJobTx(r.Context(), tx, jobs.CreateJobInput{
				Type: jobs.JobTypeParseSBOM,
				Payload: map[string]string{
					"sbom_id":    sbom.ID,
					"binding_id": binding.ID,
				},
			})
			if err != nil {
				return err
			}

			response = sbomUploadResponse{
				SBOMID:       sbom.ID,
				BindingID:    binding.ID,
				RepoID:       repo.ID,
				RepoCommitID: commit.ID,
				JobID:        job.ID,
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
			log.Printf("SBOM upload failed (repo_id=%q provider=%q org=%q slug=%q): %v", repoID, provider, org, slug, err)
			log.Printf("SBOM upload failed: %v", err)
			http.Error(w, "sbom upload failed", http.StatusInternalServerError)
			return
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

func writeJSON(w http.ResponseWriter, status int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}
