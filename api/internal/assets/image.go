package assets

import (
	"context"
	"errors"
	"os"
	"strings"

	"github.com/NorskHelsenett/spam/internal/dbutil"
	"github.com/NorskHelsenett/spam/internal/jobs"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// imageScanEnabled gates automatic IMAGE_SCAN enqueue on new digest insert.
// Off by default so rolling out the trigger does not flood the queue with
// failing jobs before runner-side support lands. Flip on via
// IMAGE_SCAN_ENABLED=true once the runner implements ImageScanExecutor.
func imageScanEnabled() bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv("IMAGE_SCAN_ENABLED")))
	return v == "1" || v == "true" || v == "yes" || v == "on"
}

type ImageDigestInput struct {
	Registry        string
	Repository      string
	Digest          string
	CreatedByUserID string
}

// UpsertImageDigest upserts a digest row. If the row is newly created, an
// IMAGE_SCAN job is enqueued in the same transaction so a scan kicks off as
// soon as a digest is observed for the first time.
func UpsertImageDigest(ctx context.Context, db *gorm.DB, input ImageDigestInput) (*ImageDigest, error) {
	var image *ImageDigest
	err := db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		img, _, err := UpsertImageDigestTx(ctx, tx, input)
		if err != nil {
			return err
		}
		image = img
		return nil
	})
	if err != nil {
		return nil, err
	}
	return image, nil
}

// UpsertImageDigestTx upserts inside an existing transaction and reports
// whether the row was freshly created. On fresh creation, an IMAGE_SCAN job
// is enqueued on the same transaction so the scan is atomic with the digest
// insert. Callers that already run inside a tx (e.g. SBOM upload handlers)
// should prefer this variant to keep the whole operation in one tx.
func UpsertImageDigestTx(ctx context.Context, tx *gorm.DB, input ImageDigestInput) (*ImageDigest, bool, error) {
	if input.Registry == "" || input.Repository == "" || input.Digest == "" {
		return nil, false, errors.New("registry, repository, and digest required")
	}

	var image ImageDigest
	where := ImageDigest{
		Registry:   input.Registry,
		Repository: input.Repository,
		Digest:     input.Digest,
	}
	result := tx.WithContext(ctx).Where(where).Attrs(ImageDigest{
		ID:              uuid.NewString(),
		CreatedByUserID: input.CreatedByUserID,
	}).FirstOrCreate(&image)

	if result.Error != nil {
		if dbutil.IsDuplicateKeyError(result.Error) {
			if err := tx.WithContext(ctx).Where(where).First(&image).Error; err != nil {
				return nil, false, err
			}
			return &image, false, nil
		}
		return nil, false, result.Error
	}

	created := result.RowsAffected == 1
	if created && imageScanEnabled() {
		if _, err := jobs.CreateJobTx(ctx, tx, jobs.CreateJobInput{
			Type: jobs.JobTypeImageScan,
			Payload: jobs.ImageScanPayload{
				ImageDigestID: image.ID,
				Registry:      image.Registry,
				Repository:    image.Repository,
				Digest:        image.Digest,
			},
		}); err != nil {
			return nil, false, err
		}
	}
	return &image, created, nil
}

func FindImageDigest(ctx context.Context, db *gorm.DB, imageID string) (*ImageDigest, error) {
	var image ImageDigest
	if err := db.WithContext(ctx).First(&image, "id = ?", imageID).Error; err != nil {
		return nil, err
	}
	return &image, nil
}
