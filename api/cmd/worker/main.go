package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/NorskHelsenett/spam/internal/cache"
	"github.com/NorskHelsenett/spam/internal/config"
	"github.com/NorskHelsenett/spam/internal/db"
	"github.com/NorskHelsenett/spam/internal/imagescan"
	"github.com/NorskHelsenett/spam/internal/jobs"
	"github.com/NorskHelsenett/spam/internal/poller"
	"github.com/NorskHelsenett/spam/internal/providerconfig"
	"github.com/NorskHelsenett/spam/internal/runner"
	"gorm.io/gorm"
)

var runExecutor jobs.RunExecutor

// Per-provider circuit breaker for CREATE_RUN failures.
type providerCircuit struct {
	consecutiveFails int
	openUntil        time.Time
}

var (
	cbMu        sync.Mutex
	cbProviders = make(map[string]*providerCircuit)
	cbThreshold = 5
	cbCooldown  = 5 * time.Minute
)

// isCircuitOpen returns true only when ALL tracked providers are tripped.
// If any provider is healthy (or its cooldown expired), we keep claiming
// because the next job might be for that healthy provider.
func isCircuitOpen() bool {
	cbMu.Lock()
	defer cbMu.Unlock()
	if len(cbProviders) == 0 {
		return false
	}
	now := time.Now()
	for _, pc := range cbProviders {
		if pc.consecutiveFails < cbThreshold || now.After(pc.openUntil) {
			return false
		}
	}
	return true
}

// isProviderCircuitOpen returns true when the specific provider's circuit is
// tripped (>= cbThreshold consecutive failures and still in cooldown).
func isProviderCircuitOpen(providerID string) bool {
	if providerID == "" {
		return false
	}
	cbMu.Lock()
	defer cbMu.Unlock()
	pc, ok := cbProviders[providerID]
	if !ok {
		return false
	}
	return pc.consecutiveFails >= cbThreshold && time.Now().Before(pc.openUntil)
}

func recordRunResult(providerID string, success bool) {
	if providerID == "" {
		return
	}
	cbMu.Lock()
	defer cbMu.Unlock()
	pc, ok := cbProviders[providerID]
	if !ok {
		pc = &providerCircuit{}
		cbProviders[providerID] = pc
	}
	if success {
		pc.consecutiveFails = 0
		return
	}
	pc.consecutiveFails++
	if pc.consecutiveFails >= cbThreshold {
		pc.openUntil = time.Now().Add(cbCooldown)
		log.Printf("circuit breaker open for provider %s: %d consecutive failures, cooling down until %s", providerID, pc.consecutiveFails, pc.openUntil.Format(time.RFC3339))
	}
}

func extractProviderID(job *jobs.Job) string {
	if len(job.Payload) == 0 {
		return ""
	}
	var p jobs.CreateRunPayload
	if err := json.Unmarshal(job.Payload, &p); err != nil {
		return ""
	}
	return p.ProviderID
}

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

const syncJobStaleTimeout = 45 * time.Second

func run() error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cfg, err := config.LoadWorker()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	gormDB, err := db.Open(ctx, db.Config{DSN: cfg.DatabaseURL})
	if err != nil {
		return fmt.Errorf("connect database: %w", err)
	}
	defer func() {
		if closeErr := db.Close(gormDB); closeErr != nil {
			log.Printf("database close error: %v", closeErr)
		}
	}()

	// Auto-migrate runner tables
	if cfg.Runner.Enabled {
		if err := gormDB.AutoMigrate(
			&runner.RunLog{}, &runner.RunSecret{}, &runner.ScannerVersion{},
			&imagescan.ImageScanRun{}, &imagescan.ImageScanArtifact{},
			&imagescan.ImageVulnFinding{},
		); err != nil {
			return fmt.Errorf("migrate runner tables: %w", err)
		}
	}

	// Start runner server if enabled
	if cfg.Runner.Enabled {
		// Create K8s client
		k8sClient, err := runner.NewK8sClient(cfg.Runner)
		if err != nil {
			return fmt.Errorf("create k8s client: %w", err)
		}

		if err := cache.EnsureTable(ctx, gormDB); err != nil {
			return fmt.Errorf("ensure kv_store table: %w", err)
		}
		cacheStore := cache.NewPostgresStore(gormDB)
		runnerServer := runner.NewServer(cfg.Runner, gormDB, k8sClient, cacheStore)

		// Create run executor
		runExecutor, err = runner.NewRunExecutor(cfg.Runner, runnerServer)
		if err != nil {
			return fmt.Errorf("create run executor: %w", err)
		}

		// Start runner HTTP server in background
		go func() {
			if err := runnerServer.Start(ctx); err != nil {
				log.Printf("runner server error: %v", err)
			}
		}()

		log.Printf("runner server enabled on port %d", cfg.Runner.HTTPPort)
	}

	// Create provider store and poller for commit-based polling
	providerStore := providerconfig.NewStore(gormDB, cfg.ProviderSecretsKey)
	if warnings := providerStore.VerifyKey(ctx); len(warnings) > 0 {
		for _, w := range warnings {
			log.Printf("WARNING: provider secret key: %s", w)
		}
	}
	commitPoller := poller.New(gormDB, providerStore)

	workerID := fmt.Sprintf("%s-%d", hostname(), os.Getpid())
	pollInterval := 2 * time.Second

	log.Printf("worker started: %s (concurrency=%d, stale_timeout=%s)", workerID, cfg.Concurrency, cfg.StaleTimeout)

	startupNow := time.Now()
	if n, err := jobs.RequeueStaleJobs(ctx, gormDB, startupNow.Add(-syncJobStaleTimeout), startupNow.Add(-cfg.StaleTimeout), startupNow); err != nil {
		log.Printf("startup stale-job requeue error: %v", err)
	} else if n > 0 {
		log.Printf("requeued %d stale running jobs on startup", n)
	}

	// Semaphore to limit concurrent job processing
	sem := make(chan struct{}, cfg.Concurrency)

	// WaitGroup to track in-flight jobs for graceful shutdown
	var wg sync.WaitGroup

	// Only allow one provider poller run at a time to avoid overlapping sync windows.
	pollSlots := make(chan struct{}, 1)
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Printf("shutdown signal received, waiting for %d in-flight jobs...", len(sem))
			wg.Wait()
			log.Printf("all jobs completed, shutting down")
			return nil

		case <-ticker.C:
			now := time.Now()
			_, _ = jobs.RequeueStaleJobs(ctx, gormDB, now.Add(-syncJobStaleTimeout), now.Add(-cfg.StaleTimeout), now)

			// Reconcile RUNNING jobs against K8s state
			if reconciler, ok := runExecutor.(jobs.RunReconciler); ok {
				if n, err := reconciler.ReconcileRunningJobs(ctx, gormDB, 2*time.Minute); err != nil {
					log.Printf("reconcile error: %v", err)
				} else if n > 0 {
					log.Printf("reconciled %d running jobs", n)
				}
			}

			// Poll providers for new commits (non-blocking — don't delay job claiming)
			select {
			case pollSlots <- struct{}{}:
				go func() {
					defer func() { <-pollSlots }()
					commitPoller.Poll(ctx)
				}()
			default:
				// Poll already in progress; skip this tick.
			}

			// Check how many CREATE_RUN jobs are currently running (async runs in K8s/Docker)
			runningRuns, err := jobs.CountRunningByType(ctx, gormDB, jobs.JobTypeCreateRun)
			if err != nil {
				log.Printf("count running runs error: %v", err)
				runningRuns = int64(cfg.Concurrency) // Assume at limit on error
			}

			// Try to claim jobs up to available concurrency slots
			for {
				// Check if we can acquire a slot (non-blocking)
				select {
				case sem <- struct{}{}:
					// Got a slot, try to claim a job
				default:
					// All slots busy, wait for next tick
					goto nextTick
				}

				// Check for shutdown
				select {
				case <-ctx.Done():
					<-sem // Release the slot we just acquired
					goto nextTick
				default:
				}

				// Determine which job types to claim based on running runs.
				// Per-provider circuit breaking is handled in processJob itself.
				//
				// IMAGE_SCAN jobs are always excluded: they are leased and
				// executed by the dedicated spam-image-scanner pod, which
				// keeps the grype/trivy vuln DB warm across many digests.
				excludeTypes := []jobs.JobType{jobs.JobTypeImageScan}
				if runningRuns >= int64(cfg.Concurrency) {
					excludeTypes = append(excludeTypes, jobs.JobTypeCreateRun)
				}

				job, err := jobs.ClaimNextJob(ctx, gormDB, workerID, time.Now(), excludeTypes...)
				if err != nil {
					log.Printf("claim job error: %v", err)
					<-sem // Release the slot
					goto nextTick
				}
				if job == nil {
					// No more jobs available
					<-sem // Release the slot
					goto nextTick
				}

				// Track if we're starting a new run
				if job.Type == jobs.JobTypeCreateRun {
					runningRuns++
				}

				// Process job in a goroutine
				wg.Add(1)
				go func(job *jobs.Job) {
					defer wg.Done()
					defer func() { <-sem }() // Release slot when done

					processJob(ctx, gormDB, job, workerID)
				}(job)
			}
		nextTick:
		}
	}
}

func processJob(ctx context.Context, db *gorm.DB, job *jobs.Job, workerID string) {
	log.Printf("processing job: id=%s type=%s attempt=%d/%d", job.ID, job.Type, job.Attempts, job.MaxAttempts)

	heartbeatCtx, cancelHeartbeat := context.WithCancel(ctx)
	if jobs.ShouldHeartbeat(job.Type) {
		go jobs.HeartbeatJob(heartbeatCtx, db, job.ID, workerID, jobs.JobHeartbeatInterval)
	}
	defer cancelHeartbeat()

	// Per-provider circuit breaker: if this specific provider is tripped, defer
	// the job immediately rather than attempting it and failing again.
	if job.Type == jobs.JobTypeCreateRun {
		if providerID := extractProviderID(job); isProviderCircuitOpen(providerID) {
			retryAt := time.Now().Add(cbCooldown)
			log.Printf("circuit breaker open for provider %s, deferring job %s until %s", providerID, job.ID, retryAt.Format(time.RFC3339))
			if _, updateErr := jobs.UpdateJobStatus(ctx, db, job.ID, jobs.JobStatusRetry, nil, "circuit breaker open", &retryAt); updateErr != nil {
				log.Printf("update job error: %v", updateErr)
			}
			return
		}
	}

	result, err := jobs.ProcessJob(ctx, db, job, runExecutor)
	now := time.Now()

	if job.Type == jobs.JobTypeCreateRun {
		recordRunResult(extractProviderID(job), err == nil)
	}

	if err != nil {
		next := (*time.Time)(nil)
		status := jobs.JobStatusFailed
		if jobs.IsRetryableWithoutCount(err) {
			// Transient condition (e.g. advisory lock held by concurrent worker).
			// Retry shortly without counting the attempt so the job doesn't exhaust retries.
			retryAt := now.Add(10 * time.Second)
			next = &retryAt
			status = jobs.JobStatusRetry
			log.Printf("job deferred (transient): id=%s type=%s error=%v retry_at=%s", job.ID, job.Type, err, retryAt.Format(time.RFC3339))
			if err := db.WithContext(ctx).Model(&jobs.Job{}).Where("id = ?", job.ID).
				Update("attempts", gorm.Expr("GREATEST(attempts - 1, 0)")).Error; err != nil {
				log.Printf("rollback attempt counter: %v", err)
			}
		} else if jobs.IsProviderUnavailable(err) {
			// Provider is temporarily down. Retry with a longer backoff and
			// roll back the attempt counter so the outage doesn't exhaust retries.
			retryAt := now.Add(5 * time.Minute)
			next = &retryAt
			status = jobs.JobStatusRetry
			log.Printf("job deferred (provider unavailable): id=%s type=%s error=%v retry_at=%s", job.ID, job.Type, err, retryAt.Format(time.RFC3339))
			if err := db.WithContext(ctx).Model(&jobs.Job{}).Where("id = ?", job.ID).
				Update("attempts", gorm.Expr("GREATEST(attempts - 1, 0)")).Error; err != nil {
				log.Printf("rollback attempt counter: %v", err)
			}
		} else if jobs.IsNonRetryable(err) {
			log.Printf("job failed (non-retryable): id=%s type=%s error=%v", job.ID, job.Type, err)
		} else if job.Attempts < job.MaxAttempts {
			retryAt := jobs.NextRetryTime(job.Attempts, job.MaxAttempts, now)
			next = &retryAt
			status = jobs.JobStatusRetry
			log.Printf("job failed (will retry): id=%s type=%s error=%v retry_at=%s", job.ID, job.Type, err, retryAt.Format(time.RFC3339))
		} else {
			log.Printf("job failed (max attempts): id=%s type=%s error=%v", job.ID, job.Type, err)
		}

		if _, updateErr := jobs.UpdateJobStatus(ctx, db, job.ID, status, nil, err.Error(), next); updateErr != nil {
			log.Printf("update job error: %v", updateErr)
			// If transitioning to RETRY failed (likely a unique constraint conflict
			// because a newer queued job of the same type already exists), fall back
			// to FAILED so the row is cleaned up rather than staying stuck in RUNNING
			// until the stale-job reaper fires.
			if status == jobs.JobStatusRetry {
				if _, failErr := jobs.UpdateJobStatus(ctx, db, job.ID, jobs.JobStatusFailed, nil, err.Error(), nil); failErr != nil {
					log.Printf("fallback-to-failed error: %v", failErr)
				}
			}
		}
		return
	}

	if job.Type == jobs.JobTypeCreateRun {
		log.Printf("run started: id=%s type=%s result=%+v", job.ID, job.Type, result)
		if _, updateErr := jobs.UpdateJobStatus(ctx, db, job.ID, jobs.JobStatusRunning, result, "", nil); updateErr != nil {
			log.Printf("update job error: %v", updateErr)
		}
		return
	}

	log.Printf("job succeeded: id=%s type=%s result=%+v", job.ID, job.Type, result)
	if _, updateErr := jobs.UpdateJobStatus(ctx, db, job.ID, jobs.JobStatusSucceeded, result, "", nil); updateErr != nil {
		log.Printf("update job error: %v", updateErr)
	}
}

func hostname() string {
	name, err := os.Hostname()
	if err != nil || name == "" {
		return "worker"
	}
	return name
}
