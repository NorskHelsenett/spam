package poller

import (
	"context"
	"encoding/json"
	"log"

	"github.com/NorskHelsenett/spam/internal/artifacts"
	"github.com/NorskHelsenett/spam/internal/assets"
	"github.com/NorskHelsenett/spam/internal/jobs"
	"github.com/NorskHelsenett/spam/internal/manifests"
	"github.com/NorskHelsenett/spam/internal/runner"
	"github.com/google/uuid"
)

// adoptRunResults links existing scan results (SBOM, secrets, manifests) to a new repo
// that shares the same commit hash as a previously finished run. This is called when the
// poller detects a commit that has already been scanned globally (e.g. a fork or renamed repo).
func (p *Poller) adoptRunResults(ctx context.Context, newRepoID, commitSHA, ref string) {
	// Find the finished job for this commit.
	var finishedRun runner.Run
	err := p.db.WithContext(ctx).
		Where("type = ?", jobs.JobTypeCreateRun).
		Where("finished_at IS NOT NULL").
		Where("(commit_hash = ? OR payload->>'commit_sha' = ?)", commitSHA, commitSHA).
		Order("finished_at DESC").
		First(&finishedRun).Error
	if err != nil {
		log.Printf("adopt: no finished run found for commit %s: %v", commitSHA, err)
		return
	}

	var payload jobs.CreateRunPayload
	if len(finishedRun.Payload) > 0 {
		if err := json.Unmarshal(finishedRun.Payload, &payload); err != nil {
			log.Printf("adopt: unmarshal payload for run %s: %v", finishedRun.ID, err)
			return
		}
	}

	originalRepoID := payload.RepoID
	if originalRepoID == newRepoID {
		return // same repo, nothing to adopt
	}

	// Create a RepoCommit for the new repo.
	newCommit, err := assets.UpsertRepoCommit(ctx, p.db, assets.RepoCommitInput{
		RepoID:    newRepoID,
		CommitSHA: commitSHA,
		Ref:       ref,
	})
	if err != nil {
		log.Printf("adopt: upsert repo commit for repo %s commit %s: %v", newRepoID, commitSHA, err)
		return
	}

	// Adopt SBOM: find the binding on the original commit and re-bind to the new commit.
	if originalRepoID != "" {
		var originalCommit assets.RepoCommit
		err := p.db.WithContext(ctx).
			Where("repo_id = ? AND commit_sha = ?", originalRepoID, commitSHA).
			First(&originalCommit).Error
		if err == nil {
			var binding artifacts.SBOMBinding
			err = p.db.WithContext(ctx).
				Where("asset_type = ? AND asset_ref_id = ?", artifacts.AssetTypeRepoCommit, originalCommit.ID).
				First(&binding).Error
			if err == nil {
				_, bindErr := artifacts.UpsertBinding(ctx, p.db, artifacts.BindingInput{
					AssetType:       artifacts.AssetTypeRepoCommit,
					AssetRefID:      newCommit.ID,
					SBOMID:          binding.SBOMID,
					Source:          binding.Source,
					CreatedByUserID: "system",
				})
				if bindErr != nil && bindErr != artifacts.ErrBindingExists {
					log.Printf("adopt: bind sbom %s to repo %s commit %s: %v", binding.SBOMID, newRepoID, commitSHA, bindErr)
				}
			}
		}
	}

	// Adopt secrets: copy RunSecret records to the new repo.
	var secrets []runner.RunSecret
	if err := p.db.WithContext(ctx).
		Where("run_id = ?", finishedRun.ID).
		Find(&secrets).Error; err == nil {
		for _, s := range secrets {
			if s.RepoID == newRepoID {
				continue // already exists
			}
			newSecret := runner.RunSecret{
				ID:           uuid.NewString(),
				RunID:        s.RunID,
				RepoID:       newRepoID,
				Findings:     s.Findings,
				FindingCount: s.FindingCount,
				CreatedAt:    s.CreatedAt,
			}
			if err := p.db.WithContext(ctx).Create(&newSecret).Error; err != nil {
				log.Printf("adopt: copy secret for repo %s run %s: %v", newRepoID, finishedRun.ID, err)
			}
		}
	}

	// Adopt manifests: copy Manifest + ManifestDependency records to the new repo.
	var mfs []manifests.Manifest
	if err := p.db.WithContext(ctx).
		Where("run_id = ?", finishedRun.ID).
		Find(&mfs).Error; err == nil {
		for _, m := range mfs {
			if m.RepoID == newRepoID {
				continue // already exists
			}
			newManifestID := uuid.NewString()

			newManifest := manifests.Manifest{
				ID:        newManifestID,
				RunID:     m.RunID,
				RepoID:    newRepoID,
				Path:      m.Path,
				Type:      m.Type,
				Content:   m.Content,
				Metadata:  m.Metadata,
				CreatedAt: m.CreatedAt,
			}
			if err := p.db.WithContext(ctx).Create(&newManifest).Error; err != nil {
				log.Printf("adopt: copy manifest for repo %s run %s: %v", newRepoID, finishedRun.ID, err)
				continue
			}

			// Copy dependencies for this manifest.
			var deps []manifests.ManifestDependency
			if err := p.db.WithContext(ctx).
				Where("manifest_id = ?", m.ID).
				Find(&deps).Error; err == nil {
				for _, d := range deps {
					newDep := manifests.ManifestDependency{
						ID:         uuid.NewString(),
						ManifestID: newManifestID,
						Name:       d.Name,
						Version:    d.Version,
						Constraint: d.Constraint,
						Ecosystem:  d.Ecosystem,
						Scope:      d.Scope,
						Direct:     d.Direct,
						CreatedAt:  d.CreatedAt,
					}
					if err := p.db.WithContext(ctx).Create(&newDep).Error; err != nil {
						log.Printf("adopt: copy dep for manifest %s: %v", newManifestID, err)
					}
				}
			}
		}
	}

	log.Printf("adopt: linked commit %s results to repo %s (from run %s)", commitSHA, newRepoID, finishedRun.ID)
}
