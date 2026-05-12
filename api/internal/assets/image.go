package assets

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"strings"
	"time"

	"github.com/NorskHelsenett/spam/internal/dbutil"
	"github.com/NorskHelsenett/spam/internal/jobs"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// imageScanFreshnessWindow is how long a completed IMAGE_SCAN counts as
// "recent enough" — within this window EnsureImageScanRecent is a no-op.
// 24h matches the cluster-presence semantics: if the same digest is
// re-observed in a cluster within a day of its last scan, we trust the
// previous result is still representative.
const imageScanFreshnessWindow = 24 * time.Hour

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
	// Only auto-enqueue a scan when the digest is currently observed
	// running in some cluster. Pre-deployment paths (SBOM upload from
	// CI, manual import, etc.) used to fire scans eagerly and waste
	// scanner time on images that may never be deployed; the actual
	// scan trigger now lives in the scam ingest deploy-time hook
	// (assets.EnsureImageScanRecent), which fires exactly when an
	// image hits a cluster.
	if created && imageScanEnabled() && imageDigestRunningInCluster(ctx, tx, image.Digest) {
		if _, err := jobs.CreateJobTx(ctx, tx, jobs.CreateJobInput{
			Type: jobs.JobTypeImageScan,
			Payload: jobs.ImageScanPayload{
				ImageDigestID: image.ID,
				Registry:      image.Registry,
				Repository:    image.Repository,
				Digest:        image.Digest,
			},
		}); err != nil {
			if dbutil.IsDuplicateKeyError(err) {
				// Concurrent ingest already queued a scan for this
				// digest — fine, the partial unique index does its job.
				return &image, created, nil
			}
			return nil, false, err
		}
	}
	return &image, created, nil
}

// imageDigestRunningInCluster reports whether the given image digest is
// currently observed in any cluster_record(kind='Container') row whose
// last event was not a DELETE. Trusts DELETE delivery; if the ingest
// pipeline drops a delete event we may slightly over-trigger, which is
// a better failure mode than silently skipping scans on long-running
// stable workloads (whose received_at can be weeks old without
// heartbeating).
func imageDigestRunningInCluster(ctx context.Context, tx *gorm.DB, digest string) bool {
	if digest == "" {
		return false
	}
	var present bool
	err := tx.WithContext(ctx).Raw(`
		SELECT EXISTS (
			SELECT 1 FROM cluster_record
			 WHERE data->>'kind' = 'Container'
			   AND data->>'digest' = ?
			   AND COALESCE(data->>'msg', '') <> 'DELETE'
		)`, digest).Scan(&present).Error
	return err == nil && present
}

// EnsureImageScanRecent enqueues an IMAGE_SCAN job for the given
// image_digest_id if no completed scan landed within
// imageScanFreshnessWindow (or the digest has never been scanned).
// Idempotent against concurrent callers via the
// ux_jobs_image_scan_active partial unique index — the duplicate-key
// error from a racing INSERT is treated as success.
//
// Called from the scam ingest pipeline on every Container observation
// whose digest is non-empty, so a digest re-entering a cluster after
// a long absence picks up a fresh scan without the caller needing to
// know whether the image_digest already existed.
func EnsureImageScanRecent(ctx context.Context, db *gorm.DB, imageDigestID string) error {
	if !imageScanEnabled() || imageDigestID == "" {
		return nil
	}

	var image ImageDigest
	if err := db.WithContext(ctx).First(&image, "id = ?", imageDigestID).Error; err != nil {
		return err
	}

	var lastFinished sql.NullTime
	if err := db.WithContext(ctx).Raw(
		`SELECT MAX(finished_at) FROM image_scan_runs
		   WHERE image_digest_id = ?
		     AND finished_at IS NOT NULL`,
		imageDigestID,
	).Scan(&lastFinished).Error; err != nil {
		return err
	}
	if lastFinished.Valid && time.Since(lastFinished.Time) < imageScanFreshnessWindow {
		return nil
	}

	_, err := jobs.CreateJob(ctx, db, jobs.CreateJobInput{
		Type: jobs.JobTypeImageScan,
		Payload: jobs.ImageScanPayload{
			ImageDigestID: image.ID,
			Registry:      image.Registry,
			Repository:    image.Repository,
			Digest:        image.Digest,
		},
	})
	if err != nil && dbutil.IsDuplicateKeyError(err) {
		return nil
	}
	return err
}
