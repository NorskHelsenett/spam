-- Fix sbom_component_view:
-- 1. Switch components CTE from LEFT JOIN LATERAL to JOIN LATERAL to prevent
--    phantom NULL rows for SBOMs with empty or absent "components" arrays.
-- 2. Recreate view_unified_repositories_vulnerabilities (dropped by CASCADE)
--    with a DISTINCT ON (repo_id) filter on trivy_scan_results so only the
--    latest scan per repo is used, preventing duplicate vuln counts on re-runs.
--
-- Note: implicit root component detection (single-component SBOMs with no
-- metadata.component) is handled in Go via countComponentsFromContent rather
-- than in SQL to avoid expensive deps/grouping CTEs during view refresh.

DROP MATERIALIZED VIEW IF EXISTS sbom_component_view CASCADE;

CREATE MATERIALIZED VIEW sbom_component_view AS
WITH latest_bindings AS (
  -- For repo_commit assets: only keep the latest commit per repo
  SELECT sb.*
  FROM sbom_bindings sb
  JOIN (
    SELECT DISTINCT ON (repo_id) id
    FROM repo_commits
    ORDER BY repo_id, created_at DESC
  ) latest_rc ON latest_rc.id = sb.asset_ref_id
  WHERE sb.asset_type = 'REPO_COMMIT'
  UNION ALL
  -- For all other asset types (e.g. image_digest): include all
  SELECT sb.*
  FROM sbom_bindings sb
  WHERE sb.asset_type != 'REPO_COMMIT'
),
sbom_json AS (
  SELECT
    s.id AS sbom_id,
    sb.asset_type,
    sb.asset_ref_id,
    convert_from(s.content_bytes, 'utf8')::jsonb AS doc
  FROM sboms s
  JOIN latest_bindings sb ON sb.sbom_id = s.id
),
components AS (
  SELECT
    sj.sbom_id,
    sj.asset_type,
    sj.asset_ref_id,
    comp AS component,
    COALESCE(comp->>'bom-ref', comp->>'purl') AS component_ref,
    CASE
      WHEN comp ? 'purl' THEN comp->>'purl'
      WHEN (comp->>'bom-ref') LIKE 'pkg:%' THEN comp->>'bom-ref'
      ELSE NULL
    END AS purl,
    comp->>'version' AS version,
    comp->>'type' AS type,
    (
      SELECT string_agg(DISTINCT license_name, ',')
      FROM (
        SELECT COALESCE(
          lic->'license'->>'id',
          lic->'license'->>'name',
          lic->>'expression'
        ) AS license_name
        FROM jsonb_array_elements(COALESCE(comp->'licenses', '[]'::jsonb)) AS lic
      ) l
      WHERE license_name IS NOT NULL AND license_name <> ''
    ) AS licenses,
    FALSE AS is_root
  FROM sbom_json sj
  -- JOIN LATERAL (not LEFT JOIN) avoids phantom NULL rows for empty arrays
  JOIN LATERAL jsonb_array_elements(COALESCE(sj.doc->'components', '[]'::jsonb)) AS comp ON TRUE
),
root_component AS (
  SELECT
    sj.sbom_id,
    sj.asset_type,
    sj.asset_ref_id,
    sj.doc->'metadata'->'component' AS component,
    COALESCE(sj.doc->'metadata'->'component'->>'bom-ref', sj.doc->'metadata'->'component'->>'purl') AS component_ref,
    CASE
      WHEN (sj.doc->'metadata'->'component') ? 'purl' THEN sj.doc->'metadata'->'component'->>'purl'
      WHEN (sj.doc->'metadata'->'component'->>'bom-ref') LIKE 'pkg:%' THEN sj.doc->'metadata'->'component'->>'bom-ref'
      ELSE NULL
    END AS purl,
    sj.doc->'metadata'->'component'->>'version' AS version,
    sj.doc->'metadata'->'component'->>'type' AS type,
    (
      SELECT string_agg(DISTINCT license_name, ',')
      FROM (
        SELECT COALESCE(
          lic->'license'->>'id',
          lic->'license'->>'name',
          lic->>'expression'
        ) AS license_name
        FROM jsonb_array_elements(COALESCE(sj.doc->'metadata'->'component'->'licenses', '[]'::jsonb)) AS lic
      ) l
      WHERE license_name IS NOT NULL AND license_name <> ''
    ) AS licenses,
    TRUE AS is_root
  FROM sbom_json sj
  WHERE sj.doc->'metadata'->'component' IS NOT NULL
)
SELECT
  c.sbom_id,
  c.asset_type,
  c.asset_ref_id,
  c.component_ref,
  c.purl,
  c.version,
  c.type,
  c.licenses,
  c.is_root,
  NULLIF(substring(c.purl from '^pkg:([^/]+)'), '') AS kind,
  NULLIF(
    replace(
      regexp_replace(
        split_part(regexp_replace(c.purl, '^pkg:[^/]+/', ''), '@', 1),
        '^.*/',
        ''
      ),
      '%40',
      '@'
    ),
    ''
  ) AS name,
  NULLIF(
    replace(
      NULLIF(
        regexp_replace(
          split_part(regexp_replace(c.purl, '^pkg:[^/]+/', ''), '@', 1),
          '/[^/]+$',
          ''
        ),
        split_part(regexp_replace(c.purl, '^pkg:[^/]+/', ''), '@', 1)
      ),
      '%40',
      '@'
    ),
    ''
  ) AS namespace,
  CASE
    WHEN c.purl IS NULL THEN NULL
    WHEN split_part(regexp_replace(c.purl, '^pkg:[^/]+/', ''), '@', 1) = '' THEN NULL
    ELSE
      replace(split_part(regexp_replace(c.purl, '^pkg:[^/]+/', ''), '@', 1), '%40', '@')
  END AS normalized_name,
  CASE
    WHEN c.purl IS NULL THEN NULL
    WHEN substring(c.purl from '^pkg:([^/]+)') = 'npm' THEN
      CASE
        WHEN NULLIF(
          replace(
            NULLIF(
              regexp_replace(
                split_part(regexp_replace(c.purl, '^pkg:[^/]+/', ''), '@', 1),
                '/[^/]+$',
                ''
              ),
              split_part(regexp_replace(c.purl, '^pkg:[^/]+/', ''), '@', 1)
            ),
            '%40',
            '@'
          ),
          ''
        ) IS NULL THEN
          NULLIF(
            replace(
              regexp_replace(
                split_part(regexp_replace(c.purl, '^pkg:[^/]+/', ''), '@', 1),
                '^.*/',
                ''
              ),
              '%40',
              '@'
            ),
            ''
          )
        ELSE
          replace(
            NULLIF(
              regexp_replace(
                split_part(regexp_replace(c.purl, '^pkg:[^/]+/', ''), '@', 1),
                '/[^/]+$',
                ''
              ),
              split_part(regexp_replace(c.purl, '^pkg:[^/]+/', ''), '@', 1)
            ),
            '%40',
            '@'
          ) || '/' || replace(
            regexp_replace(
              split_part(regexp_replace(c.purl, '^pkg:[^/]+/', ''), '@', 1),
              '^.*/',
              ''
            ),
            '%40',
            '@'
          )
      END
    WHEN substring(c.purl from '^pkg:([^/]+)') = 'golang' THEN
      replace(split_part(regexp_replace(c.purl, '^pkg:[^/]+/', ''), '@', 1), '%40', '@')
    ELSE
      replace(split_part(regexp_replace(c.purl, '^pkg:[^/]+/', ''), '@', 1), '%40', '@')
  END AS package_name,
  NULLIF(regexp_replace(split_part(c.purl, '@', 2), '[?#].*$', ''), '') AS purl_version
FROM (
  SELECT DISTINCT ON (sbom_id, asset_type, asset_ref_id, component_ref)
    sbom_id, asset_type, asset_ref_id, component, component_ref, purl, version, type, licenses, is_root
  FROM (
    SELECT * FROM components
    UNION ALL
    SELECT * FROM root_component
  ) _all
  -- is_root DESC ensures the root_component row (TRUE) wins when a component
  -- appears in both metadata.component and the top-level components array.
  ORDER BY sbom_id, asset_type, asset_ref_id, component_ref, is_root DESC
) c
WITH NO DATA;

CREATE UNIQUE INDEX IF NOT EXISTS ux_sbom_component_mv
  ON sbom_component_view (sbom_id, COALESCE(asset_type, ''), COALESCE(asset_ref_id, ''), COALESCE(component_ref, ''));

CREATE INDEX IF NOT EXISTS idx_sbom_component_mv_sbom
  ON sbom_component_view (sbom_id);

CREATE INDEX IF NOT EXISTS idx_sbom_component_mv_kind_name
  ON sbom_component_view (kind, package_name);

-- Partial index for the common dependency query pattern
CREATE INDEX IF NOT EXISTS idx_sbom_component_mv_deps
  ON sbom_component_view (kind, package_name, purl_version, sbom_id, asset_type, asset_ref_id)
  WHERE is_root = false AND purl IS NOT NULL;

-- Partial index for type='library' scans (summary, top components, correlated subquery)
CREATE INDEX IF NOT EXISTS idx_sbom_component_mv_library
  ON sbom_component_view (sbom_id, kind, package_name, purl_version, licenses)
  WHERE type = 'library' AND package_name IS NOT NULL;

-- Trigram index for ILIKE search on package_name
CREATE EXTENSION IF NOT EXISTS pg_trgm;
CREATE INDEX IF NOT EXISTS idx_sbom_component_mv_pkg_trgm
  ON sbom_component_view USING gin (package_name gin_trgm_ops)
  WHERE package_name IS NOT NULL;

-- Recreate the vulnerabilities view dropped by CASCADE above.
-- Its own migration file won't rerun (hash unchanged), so we must restore it here.
-- This version also fixes the Trivy branch to use only the latest scan per repo.
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
