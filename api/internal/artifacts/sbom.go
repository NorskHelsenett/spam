package artifacts

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"gorm.io/gorm"
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

	// Check if binding already exists for this asset
	var existing SBOMBinding
	err := db.WithContext(ctx).
		Where("asset_type = ? AND asset_ref_id = ?", input.AssetType, input.AssetRefID).
		First(&existing).Error
	if err == nil {
		return nil, ErrBindingExists
	}
	if err != gorm.ErrRecordNotFound {
		return nil, err
	}

	binding := SBOMBinding{
		ID:              uuid.NewString(),
		AssetType:       input.AssetType,
		AssetRefID:      input.AssetRefID,
		SBOMID:          input.SBOMID,
		Source:          input.Source,
		CreatedByUserID: input.CreatedByUserID,
	}

	if err := db.WithContext(ctx).Create(&binding).Error; err != nil {
		return nil, err
	}

	return &binding, nil
}
