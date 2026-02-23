-- Remove duplicate active REFRESH_SBOM_VIEWS jobs, keeping only the newest.
DELETE FROM jobs
WHERE type = 'REFRESH_SBOM_VIEWS'
  AND status IN ('QUEUED', 'RETRY')
  AND id NOT IN (
    SELECT id FROM jobs
    WHERE type = 'REFRESH_SBOM_VIEWS'
      AND status IN ('QUEUED', 'RETRY')
    ORDER BY created_at DESC
    LIMIT 1
  );

-- Only one pending refresh job at a time. If a refresh is already queued,
-- any new ingestion simply reuses it rather than piling up duplicate refreshes.
CREATE UNIQUE INDEX IF NOT EXISTS ux_jobs_refresh_sbom_views_active
  ON jobs (type)
  WHERE type = 'REFRESH_SBOM_VIEWS'
    AND status IN ('QUEUED', 'RETRY');
