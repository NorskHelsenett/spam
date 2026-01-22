package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/NorskHelsenett/spam/internal/config"
	"github.com/NorskHelsenett/spam/internal/db"
	"github.com/NorskHelsenett/spam/internal/jobs"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cfg, err := config.Load()
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

	log.Printf("worker started: %s", workerID)

	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			now := time.Now()
			_, _ = jobs.RequeueStaleJobs(ctx, gormDB, now.Add(-staleAfter), now)

			job, err := jobs.ClaimNextJob(ctx, gormDB, workerID, now)
			if err != nil {
				log.Printf("claim job error: %v", err)
				continue
			}
			if job == nil {
				continue
			}

			result, err := jobs.ProcessJob(ctx, gormDB, job)
			if err != nil {
				next := (*time.Time)(nil)
				status := jobs.JobStatusFailed
				if job.Attempts < job.MaxAttempts {
					retryAt := jobs.NextRetryTime(job.Attempts, job.MaxAttempts, now)
					next = &retryAt
					status = jobs.JobStatusRetry
				}

				if _, updateErr := jobs.UpdateJobStatus(ctx, gormDB, job.ID, status, nil, err.Error(), next); updateErr != nil {
					log.Printf("update job error: %v", updateErr)
				}
				continue
			}

			if _, updateErr := jobs.UpdateJobStatus(ctx, gormDB, job.ID, jobs.JobStatusSucceeded, result, "", nil); updateErr != nil {
				log.Printf("update job error: %v", updateErr)
			}
		}
	}
}

func hostname() string {
	name, err := os.Hostname()
	if err != nil || name == "" {
		return "worker"
	}
	return name
}
