package imagescan

import (
	"context"
	"fmt"
	"log"
	"os"
	"strconv"
	"time"

	"github.com/NorskHelsenett/spam/internal/jobs"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// Operator is the controller that reconciles the set of running scanner
// pods against the IMAGE_SCAN queue depth. One authoritative voice
// decides how many pods should exist — all other code paths (retry
// handlers, ingest triggers, reconciler passes) just mutate the queue.
// That collapses the static CronJob schedule, the per-handler "should I
// burst?" checks, and the cooldown timer into a single observe/decide/act
// loop.
//
// Design: see TODO.md and commit message.
//
// Ticker cadence is intentionally short (~10s) so retry latency is
// dominated by pod-start (~15s) rather than a scheduled tick. The
// loop is idempotent — re-running it back-to-back just sees the
// freshly-created pods and does nothing.
type Operator struct {
	db             *gorm.DB
	pods           PodController
	maxParallelism int
	spawnSpacing   time.Duration
	holderID       string
}

// PodController abstracts the Kubernetes operations the operator needs.
// Implemented by runner.K8sClient; the interface keeps the operator
// unit-testable and the imagescan package free of client-go imports.
type PodController interface {
	// CountActiveScannerPods returns the number of pods matching the
	// operator's pod label selector that are currently Pending or
	// Running. Workload counting — not Job counting — because each
	// operator-spawned Job has parallelism: 1 completions: 1.
	CountActiveScannerPods(ctx context.Context) (int, error)

	// CreateScannerJob spawns one scanner Job cloned from the template
	// CronJob. Names are unique-per-call so concurrent/back-to-back
	// spawns never collide, and finished Jobs age out via their TTL
	// without blocking future spawns.
	CreateScannerJob(ctx context.Context) error
}

// NewOperator constructs an operator bound to the given K8s pod
// controller. Returns nil when image scanning is disabled so callers
// can unconditionally start it.
func NewOperator(db *gorm.DB, pods PodController) *Operator {
	if !imageScanEnabled() {
		return nil
	}
	holderID := os.Getenv("HOSTNAME")
	if holderID == "" {
		holderID = uuid.NewString()
	}
	return &Operator{
		db:             db,
		pods:           pods,
		maxParallelism: parseMaxParallelism(),
		spawnSpacing:   parseSpawnSpacing(),
		holderID:       holderID,
	}
}

// OperatorInterval is the recommended tick cadence. Short enough that
// user-visible latency is dominated by pod-start (~15s), long enough
// that the lease-renew + queue-count queries don't hammer the DB.
const OperatorInterval = 10 * time.Second

// Run executes a single reconcile pass. Safe to call on every tick; all
// work is idempotent. Returns nil when not the leader (the other
// worker replica is driving the loop) or when there's nothing to do.
func (o *Operator) Run(ctx context.Context) error {
	if o == nil {
		return nil
	}

	leader, err := o.acquireLease(ctx)
	if err != nil {
		return fmt.Errorf("acquire lease: %w", err)
	}
	if !leader {
		return nil
	}

	queueDepth, err := o.queueDepth(ctx)
	if err != nil {
		return fmt.Errorf("queue depth: %w", err)
	}

	observed, err := o.pods.CountActiveScannerPods(ctx)
	if err != nil {
		return fmt.Errorf("count pods: %w", err)
	}

	desired := queueDepth
	if desired > o.maxParallelism {
		desired = o.maxParallelism
	}

	diff := desired - observed
	if diff <= 0 {
		return nil
	}

	log.Printf("scanner operator: queue=%d observed=%d desired=%d spawning=%d",
		queueDepth, observed, desired, diff)

	for i := 0; i < diff; i++ {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err := o.pods.CreateScannerJob(ctx); err != nil {
			// Log and stop this tick — next tick will retry the diff.
			// Not returning error so the tick loop keeps going even
			// when the k8s API is briefly unhappy.
			log.Printf("scanner operator: spawn failed (diff %d/%d): %v", i+1, diff, err)
			return nil
		}
		if i < diff-1 && o.spawnSpacing > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(o.spawnSpacing):
			}
		}
	}
	return nil
}

// queueDepth counts claimable IMAGE_SCAN jobs. Scanner pods themselves
// use the same criteria via ClaimNextJobOfType, so the operator's view
// of "work" matches what a pod will actually pick up.
func (o *Operator) queueDepth(ctx context.Context) (int, error) {
	var count int64
	err := o.db.WithContext(ctx).
		Table("jobs").
		Where("type = ? AND status IN ? AND run_at <= ?",
			jobs.JobTypeImageScan,
			[]jobs.JobStatus{jobs.JobStatusQueued, jobs.JobStatusRetry},
			time.Now()).
		Count(&count).Error
	if err != nil {
		return 0, err
	}
	return int(count), nil
}

// parseMaxParallelism reads IMAGE_SCAN_MAX_PARALLELISM. Default is 2.
// Values <=0 are clamped to 1 so the operator always produces at least
// one pod when there's queued work.
func parseMaxParallelism() int {
	raw := os.Getenv("IMAGE_SCAN_MAX_PARALLELISM")
	if raw == "" {
		return 2
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n <= 0 {
		return 2
	}
	return n
}

// parseSpawnSpacing reads IMAGE_SCAN_SPAWN_SPACING_SECONDS. Default 2s.
// Zero disables spacing (back-to-back spawns). Useful when k8s API is
// slow or rate-limited; not usually needed.
func parseSpawnSpacing() time.Duration {
	raw := os.Getenv("IMAGE_SCAN_SPAWN_SPACING_SECONDS")
	if raw == "" {
		return 2 * time.Second
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 0 {
		return 2 * time.Second
	}
	return time.Duration(n) * time.Second
}
