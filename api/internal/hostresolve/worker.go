package hostresolve

import (
	"context"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/NorskHelsenett/spam/internal/cache"
	"gorm.io/gorm"
)

// Worker periodically resolves every host in host_exposure and upserts
// the classification into host_resolution. Two clocks drive a pass:
//
//   - tickInterval (default 5m): wake on a timer regardless of signals,
//     so a quiet cluster still re-classifies eventually.
//   - Wake() (debounced): an external trigger — typically the
//     host_exposure refresh completing — that fast-paths a pass so
//     newly-ingested hosts don't sit "pending" in the UI for minutes.
//
// Within a pass, listWork pulls up to batchLimit candidates (stale rows
// + brand-new hosts), and they're resolved in parallel under a small
// worker pool so DNS load on the operator's resolver stays modest. A
// single host's lookup is bounded by Resolve's 3s timeout.
type Worker struct {
	db *gorm.DB
	cs cache.Store

	tickInterval time.Duration
	staleAfter   time.Duration
	batchLimit   int
	concurrency  int

	wake chan struct{}
	once sync.Once
}

// Defaults tuned for fleets in the low thousands of unique ingress
// hosts. tickInterval >> staleAfter would let rows drift; staleAfter <<
// tickInterval would re-resolve everything on every tick — both are
// avoided by the explicit Wake() path for "we just ingested new hosts".
const (
	defaultTickInterval = 5 * time.Minute
	defaultStaleAfter   = 6 * time.Hour
	defaultBatchLimit   = 256
	defaultConcurrency  = 16
)

// global Worker handle so the hostexposure refresh hook can fire Wake()
// without threading a pointer through main.go. Set by Start.
var (
	globalMu sync.RWMutex
	global   *Worker
)

// Start kicks the periodic loop in a background goroutine and stores
// a global reference so Wake() can be called from the hostexposure
// refresh hook without re-plumbing the worker through the call chain.
// Safe to call once at server startup; subsequent calls are no-ops.
func Start(ctx context.Context, db *gorm.DB, cs cache.Store) {
	w := &Worker{
		db:           db,
		cs:           cs,
		tickInterval: defaultTickInterval,
		staleAfter:   defaultStaleAfter,
		batchLimit:   defaultBatchLimit,
		concurrency:  defaultConcurrency,
		wake:         make(chan struct{}, 1),
	}
	globalMu.Lock()
	if global != nil {
		globalMu.Unlock()
		return
	}
	global = w
	globalMu.Unlock()

	go w.run(ctx)
}

// Wake nudges the worker to run a pass now instead of waiting for the
// next tick. Non-blocking and debounced — extra signals while a pass is
// pending are dropped because the in-flight pass will read whatever is
// in host_exposure by the time it runs.
func Wake() {
	globalMu.RLock()
	w := global
	globalMu.RUnlock()
	if w == nil {
		return
	}
	select {
	case w.wake <- struct{}{}:
	default:
	}
}

func (w *Worker) run(ctx context.Context) {
	// One immediate pass on startup so a fresh deploy doesn't wait
	// tickInterval before any hosts get classified.
	w.runOnce(ctx)

	ticker := time.NewTicker(w.tickInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			w.runOnce(ctx)
		case <-w.wake:
			w.runOnce(ctx)
		}
	}
}

func (w *Worker) runOnce(ctx context.Context) {
	items, err := listWork(ctx, w.db, w.staleAfter, w.batchLimit)
	if err != nil {
		log.Printf("hostresolve: list work: %v", err)
		return
	}
	if len(items) == 0 {
		return
	}

	workers := w.concurrency
	if workers > len(items) {
		workers = len(items)
	}
	jobs := make(chan workItem, len(items))
	for _, it := range items {
		jobs <- it
	}
	close(jobs)

	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			for it := range jobs {
				w.resolveAndUpsert(ctx, it)
			}
		}()
	}
	wg.Wait()
}

func (w *Worker) resolveAndUpsert(ctx context.Context, it workItem) {
	res := Resolve(ctx, w.cs, it.Host)
	classification := Classify(res, it.LBIPs)
	ips := strings.Join(res.IPs, ",")
	if err := upsert(ctx, w.db, it.Host, classification, ips, it.LBIPs); err != nil {
		// Don't log every host — a flaky DB during shutdown can
		// spam. Print one line per failed row at debug-ish verbosity
		// using the host so operators can correlate.
		log.Printf("hostresolve: upsert %s: %v", it.Host, err)
	}
}
