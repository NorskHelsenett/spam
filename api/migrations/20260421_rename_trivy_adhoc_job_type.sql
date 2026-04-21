-- Rename the ad-hoc SBOM vulnerability-scan job type from the legacy
-- TRIVY_ADHOC_SCAN label (named after the original scanner) to the
-- scanner-agnostic SBOM_ADHOC_SCAN. Go constants, routes, env vars,
-- and UI labels have been renamed alongside this; persisted job-queue
-- rows need the DB value updated or the worker stops recognising them.
--
-- The trivy_scan_results storage table is deliberately NOT renamed —
-- grype results are written there unchanged, and renaming would force
-- a heavyweight data migration with no user-visible benefit.

UPDATE jobs
   SET type = 'SBOM_ADHOC_SCAN'
 WHERE type = 'TRIVY_ADHOC_SCAN';
