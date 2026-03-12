-- Allow Trivy to retain scan history so the dashboard can build daily trends.
-- The latest-scan views already deduplicate by repo_id/scanned_at when needed.

DROP INDEX IF EXISTS ux_trivy_scan_results_sbom_id;

CREATE INDEX IF NOT EXISTS idx_trivy_scan_results_sbom_scanned_at
    ON trivy_scan_results (sbom_id, scanned_at DESC);
