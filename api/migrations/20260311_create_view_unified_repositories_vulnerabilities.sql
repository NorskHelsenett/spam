-- view_unified_repositories_vulnerabilities is a regular view that merges Trivy and OSV vulnerability
-- data per repository. OSV rows are only included when Trivy does not already
-- report the same vuln_id for that repo, preventing double-counting.
DROP VIEW IF EXISTS view_unified_repositories_vulnerabilities;

CREATE VIEW view_unified_repositories_vulnerabilities AS
-- Trivy: one row per (vuln, package, repo), latest scan only
SELECT
    tsr.repo_id::text                                          AS repo_id,
    COALESCE(repo.org || '/' || repo.slug, tsr.repo_id::text) AS repo_slug,
    vuln->>'VulnerabilityID'                                   AS vuln_id,
    COALESCE(vuln->>'Severity', 'UNKNOWN')                     AS severity,
    vuln->>'PkgName'                                           AS pkg_name,
    COALESCE(vuln->>'InstalledVersion', '')                    AS installed_version,
    COALESCE(vuln->>'FixedVersion', '')                        AS fixed_version,
    COALESCE(vuln->>'Title', '')                               AS title,
    COALESCE(vuln->>'Description', '')                         AS description,
    'trivy'                                                    AS source,
    tsr.scanned_at
FROM (
    SELECT DISTINCT ON (repo_id) *
    FROM trivy_scan_results
    ORDER BY repo_id, scanned_at DESC
) tsr
LEFT JOIN repos repo ON repo.id = tsr.repo_id
CROSS JOIN LATERAL jsonb_array_elements(tsr.raw_json->'Results') AS result(result)
CROSS JOIN LATERAL jsonb_array_elements(result.result->'Vulnerabilities') AS vuln(vuln)

UNION ALL

-- OSV: one row per (vuln, repo), only when Trivy doesn't already cover it
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
          FROM trivy_scan_results tsr2
          CROSS JOIN LATERAL jsonb_array_elements(tsr2.raw_json->'Results') AS tr(result)
          CROSS JOIN LATERAL jsonb_array_elements(tr.result->'Vulnerabilities') AS tv(vuln)
          WHERE tsr2.repo_id = rc.repo_id
            AND tv.vuln->>'VulnerabilityID' = cv.vuln_id
      )
    ORDER BY cv.vuln_id, rc.repo_id, cv.checked_at DESC
) osv_deduped;
