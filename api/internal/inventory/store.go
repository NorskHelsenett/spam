package inventory

import (
	"context"
	"strings"

	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type UpsertComponentInput struct {
	Name      string
	PURL      string
	Ecosystem string
}

func UpsertComponent(ctx context.Context, db *gorm.DB, input UpsertComponentInput) (*Component, error) {
	if input.Name == "" {
		return nil, nil
	}

	ecosystem := input.Ecosystem
	if ecosystem == "" && input.PURL != "" {
		ecosystem = ecosystemFromPURL(input.PURL)
	}

	var component Component
	if input.PURL != "" {
		component = Component{
			ID:        uuid.NewString(),
			Name:      input.Name,
			PURL:      input.PURL,
			Ecosystem: ecosystem,
		}
		result := db.WithContext(ctx).Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "purl"}},
			DoNothing: true,
		}).Create(&component)
		if result.Error != nil {
			return nil, result.Error
		}
		if result.RowsAffected == 0 {
			if err := db.WithContext(ctx).Where("purl = ?", input.PURL).First(&component).Error; err != nil {
				return nil, err
			}
		}
		return &component, nil
	}

	if err := db.WithContext(ctx).
		Where("name = ? AND ecosystem = ?", input.Name, ecosystem).
		First(&component).Error; err != nil {
		if err != gorm.ErrRecordNotFound {
			return nil, err
		}
		component = Component{
			ID:        uuid.NewString(),
			Name:      input.Name,
			PURL:      "",
			Ecosystem: ecosystem,
		}
		if err := db.WithContext(ctx).Create(&component).Error; err != nil {
			return nil, err
		}
	}

	return &component, nil
}

func UpsertComponentVersion(ctx context.Context, db *gorm.DB, componentID, version string) (*ComponentVersion, error) {
	if componentID == "" {
		return nil, nil
	}

	cv := ComponentVersion{
		ID:          uuid.NewString(),
		ComponentID: componentID,
		Version:     version,
	}

	result := db.WithContext(ctx).Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "component_id"}, {Name: "version"}},
		DoNothing: true,
	}).Create(&cv)
	if result.Error != nil {
		return nil, result.Error
	}
	if result.RowsAffected == 0 {
		if err := db.WithContext(ctx).
			Where("component_id = ? AND version = ?", componentID, version).
			First(&cv).Error; err != nil {
			return nil, err
		}
	}

	return &cv, nil
}

func UpsertSBOMComponent(ctx context.Context, db *gorm.DB, sbomID, componentVersionID, scope string) error {
	if sbomID == "" || componentVersionID == "" {
		return nil
	}

	link := SBOMComponent{
		ID:                 uuid.NewString(),
		SBOMID:             sbomID,
		ComponentVersionID: componentVersionID,
		Scope:              scope,
	}

	return db.WithContext(ctx).Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "sbom_id"}, {Name: "component_version_id"}},
		DoNothing: true,
	}).Create(&link).Error
}

func ecosystemFromPURL(purl string) string {
	trimmed := strings.TrimSpace(purl)
	if !strings.HasPrefix(trimmed, "pkg:") {
		return ""
	}
	trimmed = strings.TrimPrefix(trimmed, "pkg:")
	if trimmed == "" {
		return ""
	}
	parts := strings.SplitN(trimmed, "/", 2)
	return parts[0]
}
