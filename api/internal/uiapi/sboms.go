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
	"github.com/NorskHelsenett/spam/internal/providerconfig"
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
					CommitSHA:       commitSHA,
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

			sbomID, bindingID, err := artifacts.StoreSBOM(
				r.Context(), tx,
				artifacts.SBOMInput{
					Format:           format,
					ContentHash:      hash[:],
					ContentBytes:     content,
					IngestedByUserID: user.ID,
				},
				bindingInput,
			)
			if err != nil {
				return err
			}

			response.SBOMID = sbomID
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
		var providerInstanceID string
		var pi providerconfig.ProviderInstance
		err := tx.WithContext(ctx).
			Where("type = ? AND enabled = true AND (owner_path = '' OR ? = owner_path OR ? LIKE owner_path || '/%')", provider, org, org).
			Order("CASE WHEN owner_path != '' THEN 0 ELSE 1 END, created_at").
			First(&pi).Error
		if err == nil {
			providerInstanceID = pi.ID
		}
		return assets.UpsertRepo(ctx, tx, assets.RepoInput{
			Provider:           provider,
			Org:                org,
			Slug:               slug,
			CreatedByUserID:    createdBy,
			ProviderInstanceID: providerInstanceID,
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

// cycloneDXComponent holds the fields extracted from a CycloneDX component
// entry, mirroring what the sbom_component_view materialized view computes in SQL.
type cycloneDXComponent struct {
	BomRef  string
	Purl    string
	Name    string
	Version string
	Type    string
}

// countComponentsFromContent parses raw SBOM bytes and returns the component
// count without relying on the materialized view. Used as a fallback when the
// view has not yet been refreshed after a run completes.
func countComponentsFromContent(format string, content []byte) int {
	if len(content) == 0 {
		return 0
	}
	switch format {
	case "cyclonedx-json":
		var doc struct {
			Metadata struct {
				Component struct {
					BomRef string `json:"bom-ref"`
					Purl   string `json:"purl"`
				} `json:"component"`
			} `json:"metadata"`
			Components []struct {
				BomRef string `json:"bom-ref"`
				Purl   string `json:"purl"`
			} `json:"components"`
			Dependencies []struct {
				Ref       string   `json:"ref"`
				DependsOn []string `json:"dependsOn"`
			} `json:"dependencies"`
		}
		if err := json.Unmarshal(content, &doc); err != nil {
			return 0
		}
		rootRef := doc.Metadata.Component.BomRef
		rootPurl := doc.Metadata.Component.Purl
		if rootRef == "" {
			rootRef = rootPurl
		}
		if rootRef == "" {
			rootRef = cycloneDXDependencyGraphRoot(doc.Components, doc.Dependencies)
		}
		count := 0
		for _, c := range doc.Components {
			componentRef := firstNonEmpty(c.BomRef, c.Purl)
			if rootRef != "" && (componentRef == rootRef || (rootPurl != "" && c.Purl == rootPurl)) {
				continue
			}
			count++
		}
		return count
	case "spdx-json":
		var doc struct {
			Packages []struct{} `json:"packages"`
		}
		if err := json.Unmarshal(content, &doc); err != nil {
			return 0
		}
		n := len(doc.Packages)
		if n > 0 {
			return n - 1
		}
		return 0
	}
	return 0
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

// cycloneDXDependencyGraphRoot returns the bom-ref of the root component by
// finding the entry in dependencies.ref that no other component depends on.
// This handles SBOMs that omit metadata.component or use mismatched bom-refs.
func cycloneDXDependencyGraphRoot(
	components []struct {
		BomRef string `json:"bom-ref"`
		Purl   string `json:"purl"`
	},
	dependencies []struct {
		Ref       string   `json:"ref"`
		DependsOn []string `json:"dependsOn"`
	},
) string {
	if len(components) == 0 || len(dependencies) == 0 {
		return ""
	}
	// Build set of component refs present in the components array
	componentRefs := make(map[string]bool, len(components))
	for _, c := range components {
		if ref := firstNonEmpty(c.BomRef, c.Purl); ref != "" {
			componentRefs[ref] = true
		}
	}
	// Find all refs that are depended upon by at least one other entry
	dependedOn := make(map[string]bool)
	for _, d := range dependencies {
		for _, dep := range d.DependsOn {
			dependedOn[dep] = true
		}
	}
	// Root = a dependency entry whose ref is a known component and is not
	// depended upon by anyone else. Return the first match.
	for _, d := range dependencies {
		if componentRefs[d.Ref] && !dependedOn[d.Ref] {
			return d.Ref
		}
	}
	return ""
}

// extractCycloneDXComponents parses a CycloneDX JSON SBOM and returns the
// list of components declared in the top-level "components" array.
func extractCycloneDXComponents(payload []byte) ([]cycloneDXComponent, error) {
	var doc struct {
		Components []struct {
			BomRef  string `json:"bom-ref"`
			Purl    string `json:"purl"`
			Name    string `json:"name"`
			Version string `json:"version"`
			Type    string `json:"type"`
		} `json:"components"`
	}
	if err := json.Unmarshal(payload, &doc); err != nil {
		return nil, err
	}
	out := make([]cycloneDXComponent, 0, len(doc.Components))
	for _, c := range doc.Components {
		out = append(out, cycloneDXComponent{
			BomRef:  c.BomRef,
			Purl:    c.Purl,
			Name:    c.Name,
			Version: c.Version,
			Type:    c.Type,
		})
	}
	return out, nil
}

// sbomComponentCount returns the non-root component count for an SBOM.
// It prefers the materialized view when a root component was detected (is_root=true),
// which means the count excludes the root. If no root was detected in the view (all
// rows have is_root=false), it falls back to parsing the SBOM content directly —
// which uses the dependency graph to identify and exclude the root.
func sbomComponentCount(ctx context.Context, db *gorm.DB, sbomID, format string, content []byte) int64 {
	var rootCount int64
	_ = db.WithContext(ctx).Table("sbom_component_view").
		Where("sbom_id = ? AND is_root = true", sbomID).
		Count(&rootCount)

	var nonRootCount int64
	_ = db.WithContext(ctx).Table("sbom_component_view").
		Where("sbom_id = ? AND is_root = false", sbomID).
		Count(&nonRootCount)

	// If the view has entries and at least one is marked as root, trust it.
	if nonRootCount > 0 && rootCount > 0 {
		return nonRootCount
	}
	// No root detected in the view (root was not in metadata.component or bom-refs
	// didn't match). Use the Go parser which also tries the dependency graph.
	if parsed := int64(countComponentsFromContent(format, content)); parsed > 0 {
		return parsed
	}
	// Last resort: return the raw count from the view (may include root).
	return nonRootCount
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

		componentCount := sbomComponentCount(r.Context(), db, sbomID, sbom.Format, sbom.ContentBytes)

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
