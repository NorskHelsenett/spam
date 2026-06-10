// Package hostexposure owns the refresh gate for the host_exposure +
// exposed_digests materialised views. They project the Ingress →
// Service → Container chain that the hosts list and asset_risk both
// consume, so triggers from the SCAM ingest path land here rather than
// re-deriving the chain inline on every read.
package hostexposure

import (
	"context"
	"log"
	"sync"
	"time"

	"github.com/NorskHelsenett/spam/internal/assetrisk"
	spamdb "github.com/NorskHelsenett/spam/internal/db"
	"github.com/NorskHelsenett/spam/internal/hostresolve"
	"gorm.io/gorm"
)

// refreshMaxRuntime caps a single refresh invocation. The two MVs run
// CONCURRENTLY so reads aren't blocked, but a runaway refresh would
// still hold the advisory lock and starve subsequent triggers — the
// timeout returns the conn to the pool instead.
const refreshMaxRuntime = 5 * time.Minute

// refreshGate coalesces concurrent TriggerRefresh calls so high-volume
// ingest spikes (Container churn) don't pile up redundant refreshes.
// One refresh runs at a time; while it runs, additional triggers set a
// pending bit so the next iteration runs once more after the current
// one finishes. Mirrors the assetrisk / vulnmetrics gate.
var refreshGate struct {
	mu       sync.Mutex
	inflight bool
	pending  bool
}

// EnsureFirstPopulate blocks until host_exposure and exposed_digests
// are populated. Spawn from a startup goroutine so HTTP serving isn't
// gated on it. Multi-replica safe via the advisory lock inside
// RefreshHostExposureViews — only one replica actually does the work;
// others observe ErrRefreshLockHeld and poll. Returns on ctx cancel.
func EnsureFirstPopulate(ctx context.Context, db *gorm.DB) error {
	backoff := 2 * time.Second
	for {
		populated, err := spamdb.HostExposureViewsPopulated(ctx, db)
		if err != nil {
			log.Printf("hostexposure: check populated: %v", err)
		}
		if populated {
			return nil
		}
		if _, err := spamdb.RefreshHostExposureViews(ctx, db); err != nil && err != spamdb.ErrRefreshLockHeld {
			log.Printf("hostexposure: first populate refresh: %v", err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff):
		}
		if backoff < 30*time.Second {
			backoff *= 2
		}
	}
}

// TriggerRefresh proactively rebuilds host_exposure and exposed_digests
// in the background. Call from any signal-source change hook (see
// CallcenterHandler — Ingress / HTTPRoute / IngressRoute / Service /
// Container kinds) so the next /api/clusters/hosts request lands on a
// warm view. Safe to spam — the gate coalesces concurrent calls.
//
// After the host-exposure pair refreshes, asset_risk is also triggered
// because its internet_exposed signal joins exposed_digests; without
// the cascade triage would lag the hosts list by one ingest cycle.
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
			refreshed, err := spamdb.RefreshHostExposureViews(ctx, db)
			if err != nil && err != spamdb.ErrRefreshLockHeld {
				log.Printf("hostexposure: background refresh: %v", err)
			}
			cancel()

			// Cascade only when a REFRESH actually executed. A skipped
			// refresh (debounce window, unchanged cluster_record
			// fingerprint, or another replica mid-refresh) means
			// exposed_digests didn't change, so re-deriving asset_risk
			// from it would rebuild identical rows — that unconditional
			// cascade is what used to keep asset_risk rebuilding at its
			// debounce floor around the clock.
			if refreshed {
				// asset_risk's internet_exposed flag joins exposed_digests,
				// so any change we just materialized should roll forward
				// into triage. The asset_risk gate coalesces this with any
				// concurrent vuln/scan triggers, so we never over-refresh.
				assetrisk.TriggerRefresh(db)

				// Newly-ingested hosts only appear in host_exposure after
				// this refresh; nudge the hostresolve worker so the
				// summary endpoint sees them classified within seconds
				// instead of waiting for the next periodic tick.
				hostresolve.Wake()
			}

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
