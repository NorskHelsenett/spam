package artifacts

import (
	"context"
	"errors"

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
	CreatedByUserID string
}

func UpsertSBOM(ctx context.Context, db *gorm.DB, input SBOMInput) (*SBOM, error) {
	if input.Format == "" {
		return nil, errors.New("sbom format required")
	}
	if len(input.ContentHash) == 0 {
		return nil, errors.New("content hash required")
	}

	sbom := SBOM{
		ID:               uuid.NewString(),
		Format:           input.Format,
		ContentHash:      input.ContentHash,
		ContentBytes:     input.ContentBytes,
		IngestedByUserID: input.IngestedByUserID,
	}

	result := db.WithContext(ctx).Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "content_hash"}},
		DoNothing: true,
	}).Create(&sbom)
	if result.Error != nil {
		return nil, result.Error
	}
	if result.RowsAffected == 0 {
		if err := db.WithContext(ctx).Where("content_hash = ?", input.ContentHash).First(&sbom).Error; err != nil {
			return nil, err
		}
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

	result := db.WithContext(ctx).Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "asset_type"}, {Name: "asset_ref_id"}, {Name: "sbom_id"}},
		DoNothing: true,
	}).Create(&binding)
	if result.Error != nil {
		return nil, result.Error
	}
	if result.RowsAffected == 0 {
		if err := db.WithContext(ctx).
			Where("asset_type = ? AND asset_ref_id = ? AND sbom_id = ?", input.AssetType, input.AssetRefID, input.SBOMID).
			First(&binding).Error; err != nil {
			return nil, err
		}
	}

	return &binding, nil
}
