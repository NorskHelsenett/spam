package artifacts

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

var ErrBindingExists = errors.New("sbom binding already exists for this asset")

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
	result := db.WithContext(ctx).Where(SBOM{
		ContentHash: input.ContentHash,
	}).Attrs(SBOM{
		ID:               uuid.NewString(),
		Format:           input.Format,
		ContentBytes:     input.ContentBytes,
		IngestedByUserID: input.IngestedByUserID,
	}).FirstOrCreate(&sbom)

	if result.Error != nil {
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
		CreatedByUserID: input.CreatedByUserID,
	}

	// Use ON CONFLICT to handle race conditions atomically.
	// The unique constraint on (asset_type, asset_ref_id) ensures only one binding per asset.
	result := db.WithContext(ctx).
		Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "asset_type"}, {Name: "asset_ref_id"}},
			DoNothing: true,
		}).
		Create(&binding)

	if result.Error != nil {
		return nil, result.Error
	}

	// If no rows were affected, binding already exists
	if result.RowsAffected == 0 {
		return nil, ErrBindingExists
	}

	return &binding, nil
}
