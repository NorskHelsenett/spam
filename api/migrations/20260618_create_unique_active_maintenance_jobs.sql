-- Self-rescheduling maintenance jobs (REFRESH_MV, PRUNE_JOBS) follow the
-- same pattern as FETCH_KEV / FETCH_EPSS: each handler enqueues its next
-- run on success, and EnsureMaintenanceJobsScheduled backfills the first
-- run at worker boot. The partial unique index keeps multi-replica startup
-- races from queueing duplicates — the second insert hits the constraint
-- and silently no-ops (the worker treats the duplicate-key error as a
-- success, just like the feed jobs).

CREATE UNIQUE INDEX IF NOT EXISTS ux_jobs_refresh_mv_active
  ON jobs (type)
  WHERE type = 'REFRESH_MV'
    AND status IN ('QUEUED', 'RETRY');

CREATE UNIQUE INDEX IF NOT EXISTS ux_jobs_prune_jobs_active
  ON jobs (type)
  WHERE type = 'PRUNE_JOBS'
    AND status IN ('QUEUED', 'RETRY');
