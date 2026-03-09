-- Only one pending OSV scan job at a time.
CREATE UNIQUE INDEX IF NOT EXISTS ux_jobs_osv_scan_active
  ON jobs (type)
  WHERE type = 'OSV_SCAN'
    AND status IN ('QUEUED', 'RETRY');
