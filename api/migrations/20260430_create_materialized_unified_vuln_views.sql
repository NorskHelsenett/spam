-- Replace the regular views view_unified_repositories_vulnerabilities and
-- view_unified_image_vulnerabilities with materialized equivalents. The
-- regular views re-run jsonb_array_elements over sbom_scan_results.raw_json
-- on every query — fine at low scale, fatal at any real volume (the API
-- gateway times out at 504 on filtered queries).
--
-- Both MVs are created WITH NO DATA so this migration is instantaneous —
-- k8s container init does not block on the build. The first populate
-- happens asynchronously from the server's startup goroutine via
-- vulnmetrics.TriggerRefresh, which calls db.RefreshVulnUnifiedViews.
-- Subsequent refreshes use REFRESH ... CONCURRENTLY so readers always see
-- the previous snapshot during the rebuild — no empty window. CONCURRENTLY
-- requires a unique index on the MV; that's the primary purpose of the
-- (asset_id, vuln_id, pkg_name, installed_version, source) composite below.
-- Filter-supporting indexes follow.
--
-- Two semantic changes from the regular views:
--   1. cve_year smallint extracted from vuln_id, indexed. Replaces the
--      leading-wildcard ILIKE the API used for the year filter.
--   2. SELECT DISTINCT ON the natural key. The legacy views could emit
--      duplicate rows when grype reported the same (vuln, pkg, version)
--      at multiple file paths; the API's GROUP BY collapsed those, but
--      the MV's unique index needs deduped input. End-result counts are
--      unchanged because the API still groups by canonical_id.

DROP VIEW IF EXISTS view_unified_repositories_vulnerabilities;

CREATE MATERIALIZED VIEW view_unified_repositories_vulnerabilities AS
WITH grype_findings AS (
    SELECT DISTINCT ON (
        tsr.repo_id,
        m->'vulnerability'->>'id',
        COALESCE(m->'artifact'->>'name', ''),
        COALESCE(m->'artifact'->>'version', '')
    )
        tsr.repo_id::text                                          AS repo_id,
        COALESCE(repo.org || '/' || repo.slug, tsr.repo_id::text)  AS repo_slug,
        m->'vulnerability'->>'id'                                  AS vuln_id,
        COALESCE(UPPER(m->'vulnerability'->>'severity'), 'UNKNOWN') AS severity,
        COALESCE(m->'artifact'->>'name', '')                       AS pkg_name,
        COALESCE(m->'artifact'->>'version', '')                    AS installed_version,
        COALESCE(
            (SELECT string_agg(v::text, ', ')
             FROM jsonb_array_elements_text(m->'vulnerability'->'fix'->'versions') v),
            ''
        )                                                          AS fixed_version,
        COALESCE(m->'vulnerability'->>'id', '')                    AS title,
        COALESCE(m->'vulnerability'->>'description', '')           AS description,
        'grype'::text                                              AS source,
        tsr.scanned_at,
        NULLIF(substring(m->'vulnerability'->>'id' from '-(\d{4})-'), '')::smallint AS cve_year
    FROM (
        SELECT DISTINCT ON (repo_id) *
        FROM sbom_scan_results
        ORDER BY repo_id, scanned_at DESC
    ) tsr
    LEFT JOIN repos repo ON repo.id = tsr.repo_id
    CROSS JOIN LATERAL jsonb_array_elements(COALESCE(tsr.raw_json->'matches', '[]'::jsonb)) AS m(m)
    WHERE m->'vulnerability'->>'id' IS NOT NULL
      AND m->'vulnerability'->>'id' <> ''
    ORDER BY
        tsr.repo_id,
        m->'vulnerability'->>'id',
        COALESCE(m->'artifact'->>'name', ''),
        COALESCE(m->'artifact'->>'version', ''),
        tsr.scanned_at DESC
),
osv_findings AS (
    SELECT DISTINCT ON (
        rc.repo_id,
        cv.vuln_id,
        COALESCE(sc.package_name, sc.name, cv.purl),
        COALESCE(sc.purl_version, '')
    )
        rc.repo_id::text                                           AS repo_id,
        COALESCE(r2.org || '/' || r2.slug, rc.repo_id::text)       AS repo_slug,
        cv.vuln_id,
        COALESCE(NULLIF(cv.severity, ''), 'UNKNOWN')               AS severity,
        COALESCE(sc.package_name, sc.name, cv.purl)                AS pkg_name,
        COALESCE(sc.purl_version, '')                              AS installed_version,
        COALESCE(cv.fixed_in, '')                                  AS fixed_version,
        COALESCE(cv.summary, '')                                   AS title,
        COALESCE(cv.description, '')                               AS description,
        'osv'::text                                                AS source,
        cv.checked_at                                              AS scanned_at,
        NULLIF(substring(cv.vuln_id from '-(\d{4})-'), '')::smallint AS cve_year
    FROM component_vulnerabilities cv
    JOIN sbom_component_view sc ON sc.purl = cv.purl AND sc.is_root = false
    JOIN repo_commits rc ON rc.id = sc.asset_ref_id AND sc.asset_type = 'REPO_COMMIT'
    LEFT JOIN repos r2 ON r2.id = rc.repo_id
    WHERE cv.vuln_id IS NOT NULL
      AND cv.vuln_id <> ''
      AND cv.vuln_id <> '_none'
      AND NOT EXISTS (
          SELECT 1
          FROM sbom_scan_results tsr2
          CROSS JOIN LATERAL jsonb_array_elements(COALESCE(tsr2.raw_json->'matches', '[]'::jsonb)) AS tm(m)
          WHERE tsr2.repo_id = rc.repo_id
            AND tm.m->'vulnerability'->>'id' = cv.vuln_id
      )
    ORDER BY
        rc.repo_id,
        cv.vuln_id,
        COALESCE(sc.package_name, sc.name, cv.purl),
        COALESCE(sc.purl_version, ''),
        cv.checked_at DESC
)
SELECT * FROM grype_findings
UNION ALL
SELECT * FROM osv_findings
WITH NO DATA;

CREATE UNIQUE INDEX idx_view_unified_repos_vulns_unique
    ON view_unified_repositories_vulnerabilities
    (repo_id, vuln_id, pkg_name, installed_version, source);

CREATE INDEX idx_view_unified_repos_vulns_severity
    ON view_unified_repositories_vulnerabilities (severity);

CREATE INDEX idx_view_unified_repos_vulns_vuln_id
    ON view_unified_repositories_vulnerabilities (vuln_id);

CREATE INDEX idx_view_unified_repos_vulns_repo_id
    ON view_unified_repositories_vulnerabilities (repo_id);

CREATE INDEX idx_view_unified_repos_vulns_cve_year
    ON view_unified_repositories_vulnerabilities (cve_year);

CREATE INDEX idx_view_unified_repos_vulns_source
    ON view_unified_repositories_vulnerabilities (source);

CREATE INDEX idx_view_unified_repos_vulns_fixable
    ON view_unified_repositories_vulnerabilities (repo_id)
    WHERE fixed_version <> '';


DROP VIEW IF EXISTS view_unified_image_vulnerabilities;

CREATE MATERIALIZED VIEW view_unified_image_vulnerabilities AS
SELECT DISTINCT ON (
    f.image_digest_id,
    f.vuln_id,
    COALESCE(f.pkg_name, ''),
    COALESCE(f.installed_version, ''),
    f.scanner
)
    f.image_digest_id::text                                            AS image_id,
    COALESCE(NULLIF(id.registry, '') || '/' || id.repository,
             id.repository, id.id::text)                              AS image_slug,
    COALESCE(id.digest, '')                                           AS image_digest,
    COALESCE(id.source_repo_id, '')                                   AS source_repo_id,
    COALESCE(id.verified_source, false)                               AS verified_source,
    f.vuln_id                                                         AS vuln_id,
    COALESCE(NULLIF(f.severity, ''), 'UNKNOWN')                       AS severity,
    COALESCE(f.pkg_name, '')                                          AS pkg_name,
    COALESCE(f.installed_version, '')                                 AS installed_version,
    COALESCE(f.fixed_version, '')                                     AS fixed_version,
    COALESCE(f.title, '')                                             AS title,
    COALESCE(f.description, '')                                       AS description,
    f.scanner                                                         AS source,
    isr.finished_at                                                   AS scanned_at,
    NULLIF(substring(f.vuln_id from '-(\d{4})-'), '')::smallint       AS cve_year
FROM image_vuln_findings f
JOIN image_digests id ON id.id = f.image_digest_id
LEFT JOIN image_scan_runs isr ON isr.id = f.scan_run_id
WHERE f.vuln_id IS NOT NULL
  AND f.vuln_id <> ''
  AND f.vuln_id <> '_none'
ORDER BY
    f.image_digest_id,
    f.vuln_id,
    COALESCE(f.pkg_name, ''),
    COALESCE(f.installed_version, ''),
    f.scanner,
    isr.finished_at DESC NULLS LAST
WITH NO DATA;

CREATE UNIQUE INDEX idx_view_unified_image_vulns_unique
    ON view_unified_image_vulnerabilities
    (image_id, vuln_id, pkg_name, installed_version, source);

CREATE INDEX idx_view_unified_image_vulns_severity
    ON view_unified_image_vulnerabilities (severity);

CREATE INDEX idx_view_unified_image_vulns_vuln_id
    ON view_unified_image_vulnerabilities (vuln_id);

CREATE INDEX idx_view_unified_image_vulns_image_id
    ON view_unified_image_vulnerabilities (image_id);

CREATE INDEX idx_view_unified_image_vulns_cve_year
    ON view_unified_image_vulnerabilities (cve_year);

CREATE INDEX idx_view_unified_image_vulns_source
    ON view_unified_image_vulnerabilities (source);

CREATE INDEX idx_view_unified_image_vulns_fixable
    ON view_unified_image_vulnerabilities (image_id)
    WHERE fixed_version <> '';
