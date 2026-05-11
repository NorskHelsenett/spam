-- Partial unique index preventing duplicate VULN_META_FETCH jobs for
-- the same vuln_id at any moment. Mirrors the same pattern already in
-- place for CREATE_RUN, IMAGE_SCAN, FETCH_KEV/EPSS, FETCH_DEP_HEALTH,
-- OSV_SCAN, REFRESH_SBOM_VIEWS.
--
-- Why this is needed (the bug it backstops):
-- EnqueueMissingVulnMeta only excluded vuln_ids that already had a
-- vuln_metadata row. But processVulnMetaFetch only writes a row when
-- the upstream API (OSV/EUVD) returns actual data — the
-- "not_found_upstream" and "upstream_error" branches return success
-- without writing. So a vuln_id whose upstream lookup failed once
-- stayed permanently "missing" by that check, and every scan-
-- completion re-enqueued it. Production accumulated ~18.8M duplicate
-- VULN_META_FETCH jobs for ~505k distinct vuln_ids (~37x).
--
-- The companion code change in jobs/processor.go extends the missing-
-- ID query to also exclude vuln_ids already pending in jobs; this
-- index is the safety net for races between replicas / scans.
--
-- Idempotency: production already has the index (created manually
-- with CONCURRENTLY after draining the duplicates); IF NOT EXISTS
-- makes this migration a no-op there. Fresh / dev environments have
-- an empty or near-empty jobs table at boot, so the non-concurrent
-- create is instant (transaction-safe inside EnsureViews).

CREATE UNIQUE INDEX IF NOT EXISTS ux_jobs_vuln_meta_active
ON jobs ((payload ->> 'vuln_id'))
WHERE type = 'VULN_META_FETCH'
  AND status IN ('QUEUED', 'RETRY', 'RUNNING');
