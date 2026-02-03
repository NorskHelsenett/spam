package jobs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/NorskHelsenett/spam/internal/artifacts"
	"github.com/NorskHelsenett/spam/internal/assets"
	"github.com/NorskHelsenett/spam/internal/events"
	"github.com/NorskHelsenett/spam/internal/inventory"
	"gorm.io/gorm"
)

type parseSBOMPayload struct {
	SBOMID    string `json:"sbom_id"`
	BindingID string `json:"binding_id"`
}

type parseResult struct {
	SBOMID        string `json:"sbom_id"`
	Components    int    `json:"components"`
	ComponentVers int    `json:"component_versions"`
	Links         int    `json:"links"`
}

// CreateRunPayload is the payload for CREATE_RUN jobs.
type CreateRunPayload struct {
	RepoID    string `json:"repo_id,omitempty"`
	Provider  string `json:"provider,omitempty"`
	CloneURL  string `json:"clone_url"`
	Ref       string `json:"ref,omitempty"`
	CommitSHA string `json:"commit_sha,omitempty"`
}

// RunExecutor is the interface for executing runs.
type RunExecutor interface {
	ExecuteRun(ctx context.Context, runID string, payload interface{}) error
}

// ProcessJob executes job-specific handlers.
func ProcessJob(ctx context.Context, db *gorm.DB, job *Job, runExecutor RunExecutor) (interface{}, error) {
	switch job.Type {
	case JobTypeParseSBOM:
		return processParseSBOM(ctx, db, job)
	case JobTypeCreateRun:
		return processCreateRun(ctx, db, job, runExecutor)
	default:
		return nil, fmt.Errorf("unknown job type: %s", job.Type)
	}
}

func processCreateRun(ctx context.Context, db *gorm.DB, job *Job, runExecutor RunExecutor) (interface{}, error) {
	if runExecutor == nil {
		return nil, errors.New("runner not enabled")
	}

	var payload CreateRunPayload
	if len(job.Payload) == 0 {
		return nil, errors.New("missing job payload")
	}
	if err := json.Unmarshal(job.Payload, &payload); err != nil {
		return nil, fmt.Errorf("unmarshal payload: %w", err)
	}
	if payload.CloneURL == "" {
		return nil, errors.New("missing clone_url in payload")
	}

	if err := runExecutor.ExecuteRun(ctx, job.ID, payload); err != nil {
		return nil, fmt.Errorf("execute run: %w", err)
	}

	return map[string]string{
		"status": "started",
		"run_id": job.ID,
	}, nil
}

func processParseSBOM(ctx context.Context, db *gorm.DB, job *Job) (interface{}, error) {
	if job == nil {
		return nil, errors.New("job required")
	}

	var payload parseSBOMPayload
	if len(job.Payload) == 0 {
		return nil, errors.New("missing job payload")
	}
	if err := json.Unmarshal(job.Payload, &payload); err != nil {
		return nil, err
	}
	if payload.SBOMID == "" {
		return nil, errors.New("missing sbom id")
	}

	sbom, err := artifacts.FindSBOM(ctx, db, payload.SBOMID)
	if err != nil {
		return nil, fmt.Errorf("find sbom %s: %w", payload.SBOMID, err)
	}

	parsed, err := inventory.ParseSBOMFull(sbom.Format, sbom.ContentBytes)
	if err != nil {
		return nil, err
	}

	result := parseResult{SBOMID: sbom.ID}
	err = db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		stats, err := inventory.UpsertParsedSBOM(ctx, tx, sbom.ID, parsed)
		if err != nil {
			return err
		}
		result.Components = stats.Components
		result.ComponentVers = stats.ComponentVersions
		result.Links = stats.Links

		info, err := loadSBOMBroadcastInfo(ctx, tx, payload.BindingID, sbom.ID)
		if err != nil {
			return fmt.Errorf("load broadcast info: %w", err)
		}

		if err := events.EmitSBOMParsed(tx, sbom.ID, map[string]interface{}{
			"sbom_id":            sbom.ID,
			"component_count":    result.Components,
			"component_versions": result.ComponentVers,
			"links":              result.Links,
		}); err != nil {
			return fmt.Errorf("emit sbom parsed event: %w", err)
		}

		if info.SBOMID != "" {
			if err := events.NotifyEvent(tx, events.StreamEventSBOMParsed, info); err != nil {
				return fmt.Errorf("notify sbom parsed: %w", err)
			}
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	return result, nil
}

func NextRetryTime(attempts, maxAttempts int, now time.Time) time.Time {
	if maxAttempts <= 0 {
		maxAttempts = 3
	}
	delay := time.Minute
	if attempts > 1 {
		delay = time.Duration(attempts) * time.Minute
	}
	return now.Add(delay)
}

type sbomParsedBroadcast struct {
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
}

func loadSBOMBroadcastInfo(ctx context.Context, db *gorm.DB, bindingID, sbomID string) (sbomParsedBroadcast, error) {
	if bindingID == "" {
		return sbomParsedBroadcast{}, nil
	}

	binding, err := artifacts.FindBinding(ctx, db, bindingID)
	if err != nil {
		return sbomParsedBroadcast{}, err
	}

	switch binding.AssetType {
	case artifacts.AssetTypeRepoCommit:
		commit, err := assets.FindRepoCommit(ctx, db, binding.AssetRefID)
		if err != nil {
			return sbomParsedBroadcast{}, err
		}
		repo, err := assets.FindRepo(ctx, db, commit.RepoID)
		if err != nil {
			return sbomParsedBroadcast{}, err
		}

		return sbomParsedBroadcast{
			SBOMID:       sbomID,
			BindingID:    binding.ID,
			AssetType:    binding.AssetType,
			RepoID:       repo.ID,
			RepoCommitID: commit.ID,
			CommitSHA:    commit.CommitSHA,
			Provider:     repo.Provider,
			Org:          repo.Org,
			Slug:         repo.Slug,
		}, nil
	case artifacts.AssetTypeImageDigest:
		image, err := assets.FindImageDigest(ctx, db, binding.AssetRefID)
		if err != nil {
			return sbomParsedBroadcast{}, err
		}

		return sbomParsedBroadcast{
			SBOMID:          sbomID,
			BindingID:       binding.ID,
			AssetType:       binding.AssetType,
			ImageDigestID:   image.ID,
			ImageRegistry:   image.Registry,
			ImageRepository: image.Repository,
			ImageDigest:     image.Digest,
		}, nil
	default:
		return sbomParsedBroadcast{}, nil
	}
}
