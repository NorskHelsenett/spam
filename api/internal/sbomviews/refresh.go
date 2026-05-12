// Package sbomviews owns the in-process refresh gate for the SBOM
// materialised views (sbom_metadata_view + sbom_component_view).
//
// History: this used to be a queue-backed job (JobTypeRefreshSBOMViews)
// that workers leased and ran. With multiple replicas the queue
// approach burned worker slots — every replica leased a row, two of
// them blocked on the advisory lock, only one did the work. The
// REFRESH_SBOM_VIEWS pool routinely had `running=3, failed=24` from
// lock-timeout contention.
//
// The in-process pattern (mirrors hostexposure / assetrisk /
// vulnmetrics / clustersummary) coalesces concurrent triggers into one
// inflight + one pending refresh per replica, and the advisory lock
// serialises across replicas so only the winner does the REFRESH.
// Losers observe ErrRefreshLockHeld and exit cleanly without blocking
// a worker slot.
package sbomviews

import (
	"context"
	"log"
	"sync"
	"time"

	spamdb "github.com/NorskHelsenett/spam/internal/db"
	"gorm.io/gorm"
)

// refreshMaxRuntime caps a single refresh invocation. Both MVs run via
// REFRESH ... CONCURRENTLY (or a plain refresh on first populate) so
// reads aren't blocked, but a runaway refresh would still hold the
// advisory lock and starve subsequent triggers.
const refreshMaxRuntime = 5 * time.Minute

// refreshGate coalesces concurrent TriggerRefresh calls so high-volume
// SBOM ingest spikes (CI batch finishing many runs at once) don't pile
// up redundant refreshes. One refresh runs at a time; while it runs,
// additional triggers set a pending bit so the next iteration runs
// once more after the current one finishes.
var refreshGate struct {
	mu       sync.Mutex
	inflight bool
	pending  bool
}

// TriggerRefresh proactively rebuilds the SBOM MVs in the background.
// Call from any signal-source change hook (SBOM ingest, run completion,
// post-bootstrap warmup) so the next dashboard request lands on a warm
// view. Safe to spam — the gate coalesces concurrent calls.
func TriggerRefresh(db *gorm.DB) {
	refreshGate.mu.Lock()
	if refreshGate.inflight {
		refreshGate.pending = true
		refreshGate.mu.Unlock()
		return
	}
	refreshGate.inflight = true
	refreshGate.mu.Unlock()

	go func() {
		for {
			ctx, cancel := context.WithTimeout(context.Background(), refreshMaxRuntime)
			if err := spamdb.RefreshMaterializedViews(ctx, db); err != nil && err != spamdb.ErrRefreshLockHeld {
				log.Printf("sbomviews: background refresh: %v", err)
			}
			cancel()

			refreshGate.mu.Lock()
			if !refreshGate.pending {
				refreshGate.inflight = false
				refreshGate.mu.Unlock()
				return
			}
			refreshGate.pending = false
			refreshGate.mu.Unlock()
		}
	}()
}
