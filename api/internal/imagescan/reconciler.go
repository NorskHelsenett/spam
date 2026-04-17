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

// BurstTrigger spawns an adhoc scanner pod when the queue has pending
// work. Implemented by the K8s-backed RunExecutor; nil when image
// scanning is off or the worker isn't cluster-aware (tests).
type BurstTrigger interface {
	TriggerImageScanBurst(ctx context.Context) error
}

// Reconciler finds image digests that don't yet have an IMAGE_SCAN job and
// enqueues one for each. It runs periodically inside the worker so bulk
// pre-existing digests (inserted before IMAGE_SCAN_ENABLED flipped on, or
// that slipped through a failed trigger) get scanned without manual
// intervention.
//
// Once per tick, after reconciling the queue, it also asks the
// BurstTrigger to spawn an adhoc scanner pod if (and only if) there are
// claimable jobs. Combined with the scanner's pre-DB pending probe, this
// means zero wasted runtime: no pod starts unless there's work, and if
// one starts it proves its worth before the ~60s DB download.
//
// A successful or still-queued scan on a digest is enough to skip
// enqueueing — the reconciler is about *backfill*, not periodic re-scans.
// Re-scans on vuln-DB updates are a separate concern and should be
// admin-triggered.
type Reconciler struct {
	db        *gorm.DB
	burst     BurstTrigger
	batchSize int
	enabled   bool
}

// NewReconciler constructs a reconciler gated by the same IMAGE_SCAN_ENABLED
// env flag that gates the inline trigger in UpsertImageDigestTx, so
// operators only have one knob to flip. The burst trigger is optional —
// pass nil on workers without cluster access (tests) and the reconciler
// degrades to enqueue-only behaviour.
func NewReconciler(db *gorm.DB, burst BurstTrigger) *Reconciler {
	return &Reconciler{
		db:        db,
		burst:     burst,
		batchSize: 500,
		enabled:   imageScanEnabled(),
	}
}

// Enabled reports whether the reconciler should run. Callers can use this
// to skip the ticker entirely on workers where image scanning is off.
func (r *Reconciler) Enabled() bool {
	return r.enabled
}

// Run enqueues IMAGE_SCAN jobs for every digest the system knows about
// that isn't already being scanned. Two passes:
//
//	(1) Harvest distinct (registry, repository, digest) tuples from
//	    cluster_record — the live view of what's actually running in
//	    the cluster — and upsert them into image_digests. This makes
//	    the cluster the source of truth for "what needs scanning"
//	    without touching the ingest hot path in scam.CallcenterHandler.
//
//	(2) Find image_digests rows without any IMAGE_SCAN job and
//	    enqueue one. Catches both the fresh rows from pass (1) and
//	    any SBOM-uploaded digests that slipped through.
//
// Returns the number of jobs created. Safe to call on every tick; both
// passes are idempotent under concurrent workers.
func (r *Reconciler) Run(ctx context.Context) (int, error) {
	if !r.enabled {
		return 0, nil
	}

	// Pass 1 — cluster harvest. ON CONFLICT DO NOTHING makes it safe to
	// run repeatedly; the unique index (registry, repository, digest)
	// prevents duplicates. We don't care how many were actually inserted
	// here — pass 2 will pick them up by the "no IMAGE_SCAN job" predicate.
	if err := r.db.WithContext(ctx).Exec(`
		INSERT INTO image_digests (id, registry, repository, digest, created_at, created_by_user_id)
		SELECT gen_random_uuid()::text,
		       c.registry,
		       c.repository,
		       c.digest,
		       NOW(),
		       'cluster-ingest'
		FROM (
		    SELECT DISTINCT
		        data->>'registry' AS registry,
		        data->>'image'    AS repository,
		        data->>'digest'   AS digest
		    FROM cluster_record
		    WHERE data->>'kind' = 'Container'
		      AND data->>'msg' != 'DELETE'
		      AND COALESCE(data->>'registry','') != ''
		      AND COALESCE(data->>'image','')    != ''
		      AND COALESCE(data->>'digest','')   != ''
		) c
		ON CONFLICT (registry, repository, digest) DO NOTHING
	`).Error; err != nil {
		// Non-fatal — pass 2 still runs against whatever digests are
		// already present. Cluster harvest failures tend to be
		// constraint-name drift (migrations) and should surface loudly.
		log.Printf("image scan reconciler: cluster harvest: %v", err)
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

// MaybeBurst spawns an adhoc scanner pod if the queue has claimable jobs
// and a BurstTrigger is configured. Separate from Run so the worker can
// call it independently (e.g. right after a job is enqueued) without
// doing a full digest sweep. Safe to call every tick — the K8s layer
// de-dupes by fixed job name.
func (r *Reconciler) MaybeBurst(ctx context.Context) error {
	if !r.enabled || r.burst == nil {
		return nil
	}
	var count int64
	err := r.db.WithContext(ctx).
		Table("jobs").
		Where("type = ? AND status IN ? AND run_at <= ?",
			jobs.JobTypeImageScan,
			[]jobs.JobStatus{jobs.JobStatusQueued, jobs.JobStatusRetry},
			time.Now()).
		Count(&count).Error
	if err != nil {
		return fmt.Errorf("count pending image scans: %w", err)
	}
	if count == 0 {
		return nil
	}
	return r.burst.TriggerImageScanBurst(ctx)
}

// imageScanEnabled mirrors the gate in internal/assets/image.go so the
// reconciler and the inline trigger flip together. Defined here to avoid
// an assets↔imagescan import cycle.
func imageScanEnabled() bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv("IMAGE_SCAN_ENABLED")))
	return v == "1" || v == "true" || v == "yes" || v == "on"
}

// ReconcilerInterval is the default cadence recommended for callers.
// Short enough that a bulk-imported batch of digests gets picked up in
// minutes; long enough that we're not hammering the DB on every tick.
//
// This is the *check* interval: every tick we enqueue missing digests
// AND call MaybeBurst. The burst cooldown (configured on the K8s side
// via IMAGE_SCAN_BURST_MIN_GAP_SECONDS, default 30 min) is independent —
// it gates whether an actual scanner pod spawns. So with defaults we
// CHECK every 5 min but SPAWN at most every 30 min (plus however long
// the currently-running pod takes). A tick where the cooldown hasn't
// cleared is a no-op — the reconciler still enqueues, the burst just
// doesn't fire until the gap is satisfied.
const ReconcilerInterval = 5 * time.Minute
