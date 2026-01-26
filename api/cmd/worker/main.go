package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/NorskHelsenett/spam/internal/config"
	"github.com/NorskHelsenett/spam/internal/db"
	"github.com/NorskHelsenett/spam/internal/jobs"
	"gorm.io/gorm"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

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

	workerID := fmt.Sprintf("%s-%d", hostname(), os.Getpid())
	pollInterval := 2 * time.Second
	staleAfter := 10 * time.Minute

	log.Printf("worker started: %s (concurrency=%d)", workerID, cfg.Concurrency)

	// Semaphore to limit concurrent job processing
	sem := make(chan struct{}, cfg.Concurrency)

	// WaitGroup to track in-flight jobs for graceful shutdown
	var wg sync.WaitGroup

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
			_, _ = jobs.RequeueStaleJobs(ctx, gormDB, now.Add(-staleAfter), now)

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

				job, err := jobs.ClaimNextJob(ctx, gormDB, workerID, time.Now())
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

				// Process job in a goroutine
				wg.Add(1)
				go func(job *jobs.Job) {
					defer wg.Done()
					defer func() { <-sem }() // Release slot when done

					processJob(ctx, gormDB, job)
				}(job)
			}
		nextTick:
		}
	}
}

func processJob(ctx context.Context, db *gorm.DB, job *jobs.Job) {
	log.Printf("processing job: id=%s type=%s attempt=%d/%d", job.ID, job.Type, job.Attempts, job.MaxAttempts)

	result, err := jobs.ProcessJob(ctx, db, job)
	now := time.Now()

	if err != nil {
		next := (*time.Time)(nil)
		status := jobs.JobStatusFailed
		if job.Attempts < job.MaxAttempts {
			retryAt := jobs.NextRetryTime(job.Attempts, job.MaxAttempts, now)
			next = &retryAt
			status = jobs.JobStatusRetry
			log.Printf("job failed (will retry): id=%s type=%s error=%v retry_at=%s", job.ID, job.Type, err, retryAt.Format(time.RFC3339))
		} else {
			log.Printf("job failed (max attempts): id=%s type=%s error=%v", job.ID, job.Type, err)
		}

		if _, updateErr := jobs.UpdateJobStatus(ctx, db, job.ID, status, nil, err.Error(), next); updateErr != nil {
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
