// Package clustersummary owns the refresh gate for the cluster_summary
// materialised view. The MV holds the per-cluster aggregates that drive
// /api/clusters/summary; ingest hooks and the read handler both fire a
// debounced refresh through here so we never recompute the chain inline
// on a request.
package clustersummary

import (
	"context"
	"log"
	"sync"
	"time"

	spamdb "github.com/NorskHelsenett/spam/internal/db"
	"gorm.io/gorm"
)

// refreshMaxRuntime caps a single refresh invocation. The MV refreshes
// CONCURRENTLY so reads aren't blocked, but a runaway refresh would
// still hold the advisory lock and starve subsequent triggers — the
// timeout returns the conn to the pool instead.
const refreshMaxRuntime = 2 * time.Minute

// refreshGate coalesces concurrent TriggerRefresh calls so high-volume
// ingest spikes (Container churn) don't pile up redundant refreshes.
// One refresh runs at a time; while it runs, additional triggers set a
// pending bit so the next iteration runs once more after the current
// one finishes. Mirrors the assetrisk / vulnmetrics / hostexposure gate.
var refreshGate struct {
	mu       sync.Mutex
	inflight bool
	pending  bool
}

// TriggerRefresh proactively rebuilds cluster_summary in the background.
// Call from any signal-source change hook (CallcenterHandler — Container,
// Ingress, HTTPRoute, etc.) so the next /api/clusters/summary request
// lands on a warm view. Safe to spam — the gate coalesces concurrent
// calls into one inflight + one pending.
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
			if err := spamdb.RefreshClusterSummaryView(ctx, db); err != nil && err != spamdb.ErrRefreshLockHeld {
				log.Printf("clustersummary: background refresh: %v", err)
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

// EnsureFirstPopulate blocks until cluster_summary is populated. Spawn
// from a startup goroutine so HTTP serving isn't gated on it.
// Multi-replica safe via the advisory lock inside RefreshClusterSummaryView
// — only one replica actually does the REFRESH; others observe
// ErrRefreshLockHeld and poll. Returns on ctx cancel.
func EnsureFirstPopulate(ctx context.Context, db *gorm.DB) error {
	backoff := 2 * time.Second
	for {
		populated, err := spamdb.ClusterSummaryViewPopulated(ctx, db)
		if err != nil {
			log.Printf("clustersummary: check populated: %v", err)
		}
		if populated {
			return nil
		}
		if err := spamdb.RefreshClusterSummaryView(ctx, db); err != nil && err != spamdb.ErrRefreshLockHeld {
			log.Printf("clustersummary: first populate refresh: %v", err)
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
