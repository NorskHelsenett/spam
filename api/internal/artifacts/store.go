package artifacts

import (
	"context"

	"gorm.io/gorm"
)

func FindSBOM(ctx context.Context, db *gorm.DB, sbomID string) (*SBOM, error) {
	var sbom SBOM
	if err := db.WithContext(ctx).First(&sbom, "id = ?", sbomID).Error; err != nil {
		return nil, err
	}
	return &sbom, nil
}

func FindBinding(ctx context.Context, db *gorm.DB, bindingID string) (*SBOMBinding, error) {
	var binding SBOMBinding
	if err := db.WithContext(ctx).First(&binding, "id = ?", bindingID).Error; err != nil {
		return nil, err
	}
	return &binding, nil
}
