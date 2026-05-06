package artifacts

import (
	"context"
	"errors"
	"fmt"

	"github.com/NorskHelsenett/spam/internal/dbutil"
	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type SBOMInput struct {
	Format           string
	ContentHash      []byte
	ContentBytes     []byte
	IngestedByUserID string
}

type BindingInput struct {
	AssetType       string
	AssetRefID      string
	SBOMID          string
	Source          string
	CommitSHA       string
	CreatedByUserID string
}

func UpsertSBOM(ctx context.Context, db *gorm.DB, input SBOMInput) (*SBOM, error) {
	if input.Format == "" {
		return nil, errors.New("sbom format required")
	}
	if len(input.ContentHash) == 0 {
		return nil, errors.New("content hash required")
	}

	var sbom SBOM
	where := SBOM{
		ContentHash: input.ContentHash,
	}
	result := db.WithContext(ctx).Where(where).Attrs(SBOM{
		ID:               uuid.NewString(),
		Format:           input.Format,
		ContentBytes:     input.ContentBytes,
		IngestedByUserID: input.IngestedByUserID,
	}).FirstOrCreate(&sbom)

	if result.Error != nil {
		if dbutil.IsDuplicateKeyError(result.Error) {
			if err := db.WithContext(ctx).Where(where).First(&sbom).Error; err != nil {
				return nil, err
			}
			return &sbom, nil
		}
		return nil, result.Error
	}
	return &sbom, nil
}

func UpsertBinding(ctx context.Context, db *gorm.DB, input BindingInput) (*SBOMBinding, error) {
	if input.AssetType == "" || input.AssetRefID == "" || input.SBOMID == "" || input.Source == "" {
		return nil, errors.New("binding fields required")
	}

	binding := SBOMBinding{
		ID:              uuid.NewString(),
		AssetType:       input.AssetType,
		AssetRefID:      input.AssetRefID,
		SBOMID:          input.SBOMID,
		Source:          input.Source,
		CommitSHA:       input.CommitSHA,
		CreatedByUserID: input.CreatedByUserID,
	}

	// One binding per (asset_type, asset_ref_id) — unique index enforces.
	// On conflict rotate to the newest SBOM: a rescan of the same image
	// produces new findings keyed off the new sbom_id, so we want the
	// binding to point at the latest one (old sbom rows stay referenced
	// by any historical lookups that pinned by id). Keep the original
	// binding id + created_at so FK references from anything that
	// pinned by binding id don't dangle.
	result := db.WithContext(ctx).
		Clauses(clause.OnConflict{
			Columns: []clause.Column{{Name: "asset_type"}, {Name: "asset_ref_id"}},
			DoUpdates: clause.AssignmentColumns([]string{
				"sbom_id", "source", "commit_sha", "created_by_user_id",
			}),
		}).
		Create(&binding)

	if result.Error != nil {
		return nil, result.Error
	}

	// binding.ID is the NEW uuid when we inserted, but stale when we
	// updated — fetch the canonical row so the caller sees the real id.
	var stored SBOMBinding
	if err := db.WithContext(ctx).
		Where("asset_type = ? AND asset_ref_id = ?", input.AssetType, input.AssetRefID).
		First(&stored).Error; err != nil {
		return nil, err
	}
	return &stored, nil
}

// StoreSBOM stores an SBOM and optionally creates a binding in a single transaction.
func StoreSBOM(ctx context.Context, tx *gorm.DB, sbomInput SBOMInput, bindingInput *BindingInput) (sbomID, bindingID string, err error) {
	sbom, err := UpsertSBOM(ctx, tx, sbomInput)
	if err != nil {
		return "", "", fmt.Errorf("upsert sbom: %w", err)
	}
	sbomID = sbom.ID

	if bindingInput != nil {
		bindingInput.SBOMID = sbom.ID
		binding, err := UpsertBinding(ctx, tx, *bindingInput)
		if err != nil {
			return "", "", fmt.Errorf("upsert binding: %w", err)
		}
		bindingID = binding.ID
	}

	return sbomID, bindingID, nil
}
