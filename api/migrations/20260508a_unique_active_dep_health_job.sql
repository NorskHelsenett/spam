-- Mirrors the KEV / EPSS partial unique index: prevents duplicate
-- queued FETCH_DEP_HEALTH jobs across multi-replica startup races.

CREATE UNIQUE INDEX IF NOT EXISTS ux_jobs_fetch_dep_health_active
  ON jobs (type)
  WHERE type = 'FETCH_DEP_HEALTH'
    AND status IN ('QUEUED', 'RETRY');
