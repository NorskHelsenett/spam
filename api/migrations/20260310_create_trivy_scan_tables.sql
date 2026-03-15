-- Trivy scan lease table: prevents double-scanning the same SBOM.
-- Leases expire after 30 minutes to recover from pod failures.
CREATE TABLE IF NOT EXISTS trivy_scan_leases (
    sbom_id    TEXT PRIMARY KEY,
    leased_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    leased_by  TEXT        NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL
);

-- Trivy scan results: stores per-SBOM vulnerability output with pre-computed counts.
CREATE TABLE IF NOT EXISTS trivy_scan_results (
    id               TEXT        PRIMARY KEY,
    sbom_id          TEXT        NOT NULL,
    repo_id          TEXT        NOT NULL,
    scanned_at       TIMESTAMPTZ NOT NULL,
    schema_version   INT         NOT NULL DEFAULT 0,
    artifact_name    TEXT        NOT NULL DEFAULT '',
    critical_count   INT         NOT NULL DEFAULT 0,
    high_count       INT         NOT NULL DEFAULT 0,
    medium_count     INT         NOT NULL DEFAULT 0,
    low_count        INT         NOT NULL DEFAULT 0,
    unknown_count    INT         NOT NULL DEFAULT 0,
    raw_json         JSONB,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS ux_trivy_scan_results_sbom_id
    ON trivy_scan_results (sbom_id);

CREATE INDEX IF NOT EXISTS idx_trivy_scan_results_repo_id
    ON trivy_scan_results (repo_id);

CREATE INDEX IF NOT EXISTS idx_trivy_scan_results_scanned_at
    ON trivy_scan_results (scanned_at);
