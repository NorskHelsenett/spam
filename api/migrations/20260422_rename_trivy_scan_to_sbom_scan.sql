-- Rename the Trivy-era storage tables to scanner-agnostic names to match
-- the code: the sbom-scanner migrated to grype months ago, but the tables
-- and the unified-vulnerabilities view still carried trivy-shaped column
-- names and JSON parsers. This migration takes the data-loss-and-rescan
-- route: old findings are dropped, the sbom-scanner CronJob's next run
-- repopulates sbom_scan_results from the stored SBOMs (grype doesn't pull
-- images — just reads SBOM files — so the rescan is cheap).
--
-- Columns that were trivy-specific are gone:
--   * format              (every row is grype now; no dispatch needed)
--   * schema_version      (trivy's report schema version; not in grype)
--   * artifact_name       (trivy's top-level scan target name; grype puts
--                          the equivalent under source.target)

DROP VIEW IF EXISTS view_unified_repositories_vulnerabilities;
DROP TABLE IF EXISTS trivy_scan_leases;
DROP TABLE IF EXISTS trivy_scan_results;

CREATE TABLE sbom_scan_leases (
    sbom_id     TEXT        PRIMARY KEY,
    leased_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    leased_by   TEXT        NOT NULL DEFAULT '',
    expires_at  TIMESTAMPTZ NOT NULL
);

CREATE TABLE sbom_scan_results (
    id               TEXT        PRIMARY KEY,
    sbom_id          TEXT        NOT NULL,
    repo_id          TEXT        NOT NULL,
    scanned_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    critical_count   INT         NOT NULL DEFAULT 0,
    high_count       INT         NOT NULL DEFAULT 0,
    medium_count     INT         NOT NULL DEFAULT 0,
    low_count        INT         NOT NULL DEFAULT 0,
    unknown_count    INT         NOT NULL DEFAULT 0,
    raw_json         JSONB       NOT NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_sbom_scan_results_repo_id
    ON sbom_scan_results (repo_id);

CREATE INDEX idx_sbom_scan_results_scanned_at
    ON sbom_scan_results (scanned_at);

CREATE INDEX idx_sbom_scan_results_sbom_scanned_at
    ON sbom_scan_results (sbom_id, scanned_at DESC);

-- view_unified_repositories_vulnerabilities merges grype findings
-- (sbom_scan_results.raw_json) and OSV findings (component_vulnerabilities)
-- per repository. OSV rows are only included when grype doesn't already
-- report the same vuln_id for that repo, preventing double-counting.
--
-- Grype stores matches under matches[] with lowercase keys; the previous
-- trivy-shaped view read Results[].Vulnerabilities[] with Titlecase keys.
CREATE VIEW view_unified_repositories_vulnerabilities AS
-- Grype: one row per (vuln, package, repo), latest scan only
SELECT
    tsr.repo_id::text                                         AS repo_id,
    COALESCE(repo.org || '/' || repo.slug, tsr.repo_id::text) AS repo_slug,
    m->'vulnerability'->>'id'                                 AS vuln_id,
    COALESCE(UPPER(m->'vulnerability'->>'severity'), 'UNKNOWN') AS severity,
    COALESCE(m->'artifact'->>'name', '')                      AS pkg_name,
    COALESCE(m->'artifact'->>'version', '')                   AS installed_version,
    COALESCE(
        (SELECT string_agg(v::text, ', ')
         FROM jsonb_array_elements_text(m->'vulnerability'->'fix'->'versions') v),
        ''
    )                                                         AS fixed_version,
    COALESCE(m->'vulnerability'->>'id', '')                   AS title,
    COALESCE(m->'vulnerability'->>'description', '')          AS description,
    'grype'                                                   AS source,
    tsr.scanned_at
FROM (
    SELECT DISTINCT ON (repo_id) *
    FROM sbom_scan_results
    ORDER BY repo_id, scanned_at DESC
) tsr
LEFT JOIN repos repo ON repo.id = tsr.repo_id
CROSS JOIN LATERAL jsonb_array_elements(COALESCE(tsr.raw_json->'matches', '[]'::jsonb)) AS m(m)

UNION ALL

-- OSV: one row per (vuln, repo), only when grype doesn't already cover it
SELECT
    repo_id, repo_slug, vuln_id, severity,
    pkg_name, installed_version, fixed_version,
    title, description, source, scanned_at
FROM (
    SELECT DISTINCT ON (cv.vuln_id, rc.repo_id)
        rc.repo_id::text                                           AS repo_id,
        COALESCE(r2.org || '/' || r2.slug, rc.repo_id::text)      AS repo_slug,
        cv.vuln_id,
        COALESCE(NULLIF(cv.severity, ''), 'UNKNOWN')               AS severity,
        COALESCE(sc.package_name, sc.name, cv.purl)               AS pkg_name,
        COALESCE(sc.purl_version, '')                              AS installed_version,
        COALESCE(cv.fixed_in, '')                                  AS fixed_version,
        COALESCE(cv.summary, '')                                   AS title,
        COALESCE(cv.description, '')                               AS description,
        'osv'                                                      AS source,
        cv.checked_at                                              AS scanned_at
    FROM component_vulnerabilities cv
    JOIN sbom_component_view sc ON sc.purl = cv.purl AND sc.is_root = false
    JOIN repo_commits rc ON rc.id = sc.asset_ref_id AND sc.asset_type = 'REPO_COMMIT'
    LEFT JOIN repos r2 ON r2.id = rc.repo_id
    WHERE cv.vuln_id <> '_none'
      AND NOT EXISTS (
          SELECT 1
          FROM sbom_scan_results tsr2
          CROSS JOIN LATERAL jsonb_array_elements(COALESCE(tsr2.raw_json->'matches', '[]'::jsonb)) AS tm(m)
          WHERE tsr2.repo_id = rc.repo_id
            AND tm.m->'vulnerability'->>'id' = cv.vuln_id
      )
    ORDER BY cv.vuln_id, rc.repo_id, cv.checked_at DESC
) osv_deduped;
