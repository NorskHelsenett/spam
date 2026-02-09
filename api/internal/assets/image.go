package assets

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type ImageDigestInput struct {
	Registry        string
	Repository      string
	Digest          string
	CreatedByUserID string
}

func UpsertImageDigest(ctx context.Context, db *gorm.DB, input ImageDigestInput) (*ImageDigest, error) {
	if input.Registry == "" || input.Repository == "" || input.Digest == "" {
		return nil, errors.New("registry, repository, and digest required")
	}

	var image ImageDigest
	result := db.WithContext(ctx).Where(ImageDigest{
		Registry:   input.Registry,
		Repository: input.Repository,
		Digest:     input.Digest,
	}).Attrs(ImageDigest{
		ID:              uuid.NewString(),
		CreatedByUserID: input.CreatedByUserID,
	}).FirstOrCreate(&image)

	if result.Error != nil {
		return nil, result.Error
	}
	return &image, nil
}

func FindImageDigest(ctx context.Context, db *gorm.DB, imageID string) (*ImageDigest, error) {
	var image ImageDigest
	if err := db.WithContext(ctx).First(&image, "id = ?", imageID).Error; err != nil {
		return nil, err
	}
	return &image, nil
}
