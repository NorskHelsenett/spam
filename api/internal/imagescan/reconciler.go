package imagescan

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/NorskHelsenett/spam/internal/jobs"
	"gorm.io/gorm"
)

// Reconciler finds image digests that don't yet have an IMAGE_SCAN job and
// enqueues one for each. It runs periodically inside the worker so bulk
// pre-existing digests (inserted before IMAGE_SCAN_ENABLED flipped on, or
// that slipped through a failed trigger) get scanned without manual
// intervention.
//
// A successful or still-queued scan on a digest is enough to skip
// enqueueing — the reconciler is about *backfill*, not periodic re-scans.
// Re-scans on vuln-DB updates are a separate concern and should be
// admin-triggered.
type Reconciler struct {
	db        *gorm.DB
	batchSize int
	enabled   bool
}

// NewReconciler constructs a reconciler gated by the same IMAGE_SCAN_ENABLED
// env flag that gates the inline trigger in UpsertImageDigestTx, so
// operators only have one knob to flip.
func NewReconciler(db *gorm.DB) *Reconciler {
	return &Reconciler{
		db:        db,
		batchSize: 500,
		enabled:   imageScanEnabled(),
	}
}

// Enabled reports whether the reconciler should run. Callers can use this
// to skip the ticker entirely on workers where image scanning is off.
func (r *Reconciler) Enabled() bool {
	return r.enabled
}

// Run scans for digests without an IMAGE_SCAN job and enqueues jobs for
// each. Returns the number of jobs created. Safe to call on every tick;
// the WHERE NOT EXISTS clause makes it idempotent under concurrent
// workers (the UNIQUE on ImageDigest.id prevents double-enqueue races
// here, since we filter by digest ID).
func (r *Reconciler) Run(ctx context.Context) (int, error) {
	if !r.enabled {
		return 0, nil
	}

	type row struct {
		ID         string
		Registry   string
		Repository string
		Digest     string
	}
	var rows []row
	// Find digests with NO existing IMAGE_SCAN job of any status. We don't
	// auto re-enqueue after a FAILED — that would flood the queue for a
	// persistently-unscannable digest (e.g. private-registry auth missing).
	// Operators can delete the failed job to force a re-try.
	err := r.db.WithContext(ctx).Raw(`
		SELECT id.id, id.registry, id.repository, id.digest
		FROM image_digests id
		WHERE NOT EXISTS (
			SELECT 1 FROM jobs j
			WHERE j.type = ?
			  AND j.payload->>'image_digest_id' = id.id
		)
		ORDER BY id.created_at ASC
		LIMIT ?
	`, jobs.JobTypeImageScan, r.batchSize).Scan(&rows).Error
	if err != nil {
		return 0, fmt.Errorf("query unscanned digests: %w", err)
	}
	if len(rows) == 0 {
		return 0, nil
	}

	enqueued := 0
	for _, d := range rows {
		if ctx.Err() != nil {
			break
		}
		_, err := jobs.CreateJob(ctx, r.db, jobs.CreateJobInput{
			Type: jobs.JobTypeImageScan,
			Payload: jobs.ImageScanPayload{
				ImageDigestID: d.ID,
				Registry:      d.Registry,
				Repository:    d.Repository,
				Digest:        d.Digest,
			},
		})
		if err != nil {
			// One-row failures shouldn't abort the sweep — log and continue
			// so a single bad digest doesn't block backfill for the rest.
			log.Printf("image scan reconciler: enqueue %s: %v", d.ID, err)
			continue
		}
		enqueued++
	}
	return enqueued, nil
}

// imageScanEnabled mirrors the gate in internal/assets/image.go so the
// reconciler and the inline trigger flip together. Defined here to avoid
// an assets↔imagescan import cycle.
func imageScanEnabled() bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv("IMAGE_SCAN_ENABLED")))
	return v == "1" || v == "true" || v == "yes" || v == "on"
}

// ReconcilerInterval is the default cadence recommended for callers. Short
// enough that a bulk-imported batch of digests gets picked up in minutes;
// long enough that we're not hammering the DB on every tick.
const ReconcilerInterval = 5 * time.Minute
