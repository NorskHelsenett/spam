-- Optimize sbom_component_view to only materialize the latest SBOM per repo.
-- The view now only processes the latest bound SBOM per repo_commit
-- (keyed by repo_id) plus all non-repo-commit assets.
-- The depends_on column has been removed as it is not currently used.

DROP MATERIALIZED VIEW IF EXISTS sbom_component_view;

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
  LEFT JOIN LATERAL jsonb_array_elements(COALESCE(sj.doc->'components', '[]'::jsonb)) AS comp ON TRUE
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
