package runner

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/NorskHelsenett/spam/internal/jobs"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// ReconcileRunningJobs checks RUNNING CREATE_RUN jobs against their K8s job
// state and updates the database accordingly. This catches runs whose
// WebSocket connection was lost before the runner could send a "done" message.
func (e *RunExecutor) ReconcileRunningJobs(ctx context.Context, db *gorm.DB, minAge time.Duration) (int, error) {
	cutoff := time.Now().Add(-minAge)
	var runs []Run

	if err := db.WithContext(ctx).
		Clauses(clause.Locking{Strength: "UPDATE", Options: "SKIP LOCKED"}).
		Where("type = ?", jobs.JobTypeCreateRun).
		Where("status = ?", RunStatusRunning).
		Where("k8s_job_name != ''").
		Where("updated_at < ?", cutoff).
		Limit(50).
		Find(&runs).Error; err != nil {
		return 0, fmt.Errorf("query running jobs: %w", err)
	}

	if len(runs) == 0 {
		return 0, nil
	}

	reconciled := 0
	for i := range runs {
		run := runs[i]
		if err := e.reconcileRun(ctx, db, &run); err != nil {
			log.Printf("reconcile error: run_id=%s job=%s/%s error=%v", run.ID, run.K8sNamespace, run.K8sJobName, err)
			continue
		}
		reconciled++
	}

	// Second pass: find orphaned RUNNING jobs with no k8s_job_name
	// These are jobs where the worker crashed before creating the K8s job
	var orphans []Run
	if err := db.WithContext(ctx).
		Clauses(clause.Locking{Strength: "UPDATE", Options: "SKIP LOCKED"}).
		Where("type = ?", jobs.JobTypeCreateRun).
		Where("status = ?", RunStatusRunning).
		Where("k8s_job_name = ''").
		Where("updated_at < ?", cutoff).
		Limit(50).
		Find(&orphans).Error; err != nil {
		return reconciled, fmt.Errorf("query orphaned jobs: %w", err)
	}

	for i := range orphans {
		run := orphans[i]
		log.Printf("reconcile: orphaned RUNNING job (no k8s job), re-queuing: run_id=%s", run.ID)
		if err := e.requeueRun(ctx, db, &run); err != nil {
			log.Printf("reconcile error: orphaned run_id=%s error=%v", run.ID, err)
			continue
		}
		reconciled++
	}

	if reconciled > 0 {
		log.Printf("reconciled %d jobs (%d running, %d orphaned)", reconciled, len(runs), len(orphans))
	}
	return reconciled, nil
}

func (e *RunExecutor) reconcileRun(ctx context.Context, db *gorm.DB, run *Run) error {
	k8sJob, err := e.k8s.GetJobStatus(ctx, run.K8sJobName, run.K8sNamespace)
	if err != nil {
		// K8s job not found (TTL cleaned or manually deleted)
		return e.markRunFailed(ctx, db, run, "k8s job not found")
	}

	// Job is still actively running — but check pod status for stuck error states
	if k8sJob.Status.Active > 0 {
		podStatus, podErr := e.k8s.GetPodStatus(ctx, run.K8sJobName, run.K8sNamespace)
		if podErr == nil && podStatus.IsError {
			errMsg := fmt.Sprintf("k8s pod stuck: %s: %s", podStatus.Reason, podStatus.Message)
			log.Printf("reconcile: pod in error state, marking run FAILED: run_id=%s job=%s/%s error=%s",
				run.ID, run.K8sNamespace, run.K8sJobName, errMsg)
			_ = e.k8s.DeleteJob(ctx, run.K8sJobName, run.K8sNamespace)
			return e.markRunFailed(ctx, db, run, errMsg)
		}
		// Pod is healthy or we couldn't check — touch updated_at
		return db.WithContext(ctx).
			Model(&Run{}).
			Where("id = ?", run.ID).
			Update("updated_at", time.Now()).Error
	}

	// Job succeeded in K8s
	if k8sJob.Status.Succeeded > 0 {
		log.Printf("reconcile: k8s job succeeded, marking run SUCCEEDED: run_id=%s job=%s/%s",
			run.ID, run.K8sNamespace, run.K8sJobName)
		return e.markRunSucceeded(ctx, db, run)
	}

	// Job failed in K8s
	if k8sJob.Status.Failed > 0 {
		errMsg := "k8s job failed"
		podStatus, podErr := e.k8s.GetPodStatus(ctx, run.K8sJobName, run.K8sNamespace)
		if podErr == nil && podStatus.IsError {
			errMsg = fmt.Sprintf("k8s job failed: %s: %s", podStatus.Reason, podStatus.Message)
		}
		log.Printf("reconcile: k8s job failed, marking run FAILED: run_id=%s job=%s/%s error=%s",
			run.ID, run.K8sNamespace, run.K8sJobName, errMsg)
		return e.markRunFailed(ctx, db, run, errMsg)
	}

	// No active/succeeded/failed — still pending, check pod status for errors
	podStatus, podErr := e.k8s.GetPodStatus(ctx, run.K8sJobName, run.K8sNamespace)
	if podErr == nil && podStatus.IsError {
		errMsg := fmt.Sprintf("k8s pod stuck: %s: %s", podStatus.Reason, podStatus.Message)
		log.Printf("reconcile: pod in error state (no active pods), marking run FAILED: run_id=%s job=%s/%s error=%s",
			run.ID, run.K8sNamespace, run.K8sJobName, errMsg)
		_ = e.k8s.DeleteJob(ctx, run.K8sJobName, run.K8sNamespace)
		return e.markRunFailed(ctx, db, run, errMsg)
	}
	// Pod is healthy or we couldn't check — touch updated_at
	return db.WithContext(ctx).
		Model(&Run{}).
		Where("id = ?", run.ID).
		Update("updated_at", time.Now()).Error
}

func (e *RunExecutor) requeueRun(ctx context.Context, db *gorm.DB, run *Run) error {
	now := time.Now()
	return db.WithContext(ctx).Model(&Run{}).Where("id = ?", run.ID).Updates(map[string]interface{}{
		"status":     RunStatusQueued,
		"locked_at":  nil,
		"locked_by":  "",
		"updated_at": now,
	}).Error
}

func (e *RunExecutor) markRunSucceeded(ctx context.Context, db *gorm.DB, run *Run) error {
	now := time.Now()
	return db.WithContext(ctx).Model(&Run{}).Where("id = ?", run.ID).Updates(map[string]interface{}{
		"status":      RunStatusSucceeded,
		"finished_at": now,
		"locked_at":   nil,
		"locked_by":   "",
		"updated_at":  now,
	}).Error
}

func (e *RunExecutor) markRunFailed(ctx context.Context, db *gorm.DB, run *Run, errMsg string) error {
	now := time.Now()
	return db.WithContext(ctx).Model(&Run{}).Where("id = ?", run.ID).Updates(map[string]interface{}{
		"status":      RunStatusFailed,
		"error":       errMsg,
		"finished_at": now,
		"locked_at":   nil,
		"locked_by":   "",
		"updated_at":  now,
	}).Error
}
