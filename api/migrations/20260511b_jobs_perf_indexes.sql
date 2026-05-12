-- Performance indexes for the `jobs` table, surfaced by
-- pg_stat_statements as the hottest queries in prod:
--
--   1. The worker's job-claim query filters on (type, status, run_at)
--      and orders by (run_at, created_at, id). The schema had three
--      single-column btrees (type, status, run_at) that the planner
--      couldn't combine, so claims fell back to scanning millions of
--      rows of a given type per attempt.
--
--   2. The artifact-content lookup goes
--          image_digests -> jobs (by payload->>'image_digest_id')
--                       -> image_scan_artifacts (by jobs.id)
--      The existing functional index `ux_jobs_image_scan_active` is
--      partial on `status IN ('QUEUED','RETRY','RUNNING')`, so
--      historical lookups (most of them) hit SUCCEEDED rows and the
--      index can't be used — the planner seq-scanned 20M jobs per
--      LATERAL iteration.
--
-- Production already has these indexes (created by hand with
-- CONCURRENTLY to avoid table locks on the 20M-row jobs table); the
-- IF NOT EXISTS makes this migration a no-op there. On fresh / dev
-- environments the table is tiny at boot time, so the non-concurrent
-- create completes in milliseconds.
--
-- CONCURRENTLY is deliberately not used here: EnsureViews wraps every
-- migration in a transaction, and CREATE INDEX CONCURRENTLY can't run
-- inside one. Fixing that properly is a separate improvement.

CREATE INDEX IF NOT EXISTS idx_jobs_claim_active
ON jobs (type, run_at, created_at, id)
WHERE status IN ('QUEUED', 'RETRY');

CREATE INDEX IF NOT EXISTS idx_jobs_image_scan_digest_all
ON jobs ((payload ->> 'image_digest_id'))
WHERE type = 'IMAGE_SCAN';
