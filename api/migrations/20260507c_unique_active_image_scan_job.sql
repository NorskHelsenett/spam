-- Prevent duplicate active IMAGE_SCAN jobs for the same image_digest.
-- The scam ingest pipeline calls EnsureImageScanRecent on every
-- Container observation; without this index, a flurry of pod
-- restarts on the same image would queue dozens of redundant scans.
-- The matching ON CONFLICT-style swallow in EnsureImageScanRecent
-- turns concurrent enqueue races into no-ops.
CREATE UNIQUE INDEX IF NOT EXISTS ux_jobs_image_scan_active
  ON jobs ((payload->>'image_digest_id'))
  WHERE type = 'IMAGE_SCAN'
    AND status IN ('QUEUED', 'RETRY', 'RUNNING');
