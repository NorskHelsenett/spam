-- Self-rescheduling daily feed jobs. Both run at startup and
-- enqueue their +24 h follow-up on success. The partial unique
-- index keeps multi-replica startup races from queueing duplicates;
-- the second worker hits the constraint and silently no-ops.

CREATE UNIQUE INDEX IF NOT EXISTS ux_jobs_fetch_kev_active
  ON jobs (type)
  WHERE type = 'FETCH_KEV'
    AND status IN ('QUEUED', 'RETRY');

CREATE UNIQUE INDEX IF NOT EXISTS ux_jobs_fetch_epss_active
  ON jobs (type)
  WHERE type = 'FETCH_EPSS'
    AND status IN ('QUEUED', 'RETRY');
