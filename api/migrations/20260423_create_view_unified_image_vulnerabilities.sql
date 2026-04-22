-- view_unified_image_vulnerabilities exposes grype findings for scanned
-- container images in the same row shape as the repo-side unified view.
-- The grype parser replaces image_vuln_findings in place on every scan
-- (see imagescan/grype_parser.go), so a plain SELECT is already "latest
-- per image" — no DISTINCT ON needed.
--
-- Columns mirror view_unified_repositories_vulnerabilities with the repo
-- identity replaced by image identity. source_repo_id + verified_source
-- are surfaced so the ACL layer can scope image vulns through the same
-- "verified source repo" inheritance used elsewhere (see acl_helpers.go).
DROP VIEW IF EXISTS view_unified_image_vulnerabilities;

CREATE VIEW view_unified_image_vulnerabilities AS
SELECT
    f.image_digest_id::text                                            AS image_id,
    COALESCE(NULLIF(id.registry, '') || '/' || id.repository,
             id.repository, id.id::text)                              AS image_slug,
    COALESCE(id.digest, '')                                           AS image_digest,
    COALESCE(id.source_repo_id, '')                                   AS source_repo_id,
    COALESCE(id.verified_source, false)                               AS verified_source,
    f.vuln_id                                                         AS vuln_id,
    COALESCE(NULLIF(f.severity, ''), 'UNKNOWN')                      AS severity,
    COALESCE(f.pkg_name, '')                                          AS pkg_name,
    COALESCE(f.installed_version, '')                                AS installed_version,
    COALESCE(f.fixed_version, '')                                     AS fixed_version,
    COALESCE(f.title, '')                                             AS title,
    COALESCE(f.description, '')                                       AS description,
    f.scanner                                                         AS source,
    isr.finished_at                                                   AS scanned_at
FROM image_vuln_findings f
JOIN image_digests id ON id.id = f.image_digest_id
LEFT JOIN image_scan_runs isr ON isr.id = f.scan_run_id
WHERE f.vuln_id <> ''
  AND f.vuln_id <> '_none';
