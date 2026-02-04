DROP MATERIALIZED VIEW IF EXISTS sbom_component_view;
DROP VIEW IF EXISTS sbom_component_view;

CREATE MATERIALIZED VIEW sbom_component_view AS
WITH sbom_json AS (
  SELECT
    s.id AS sbom_id,
    sb.asset_type,
    sb.asset_ref_id,
    convert_from(s.content_bytes, 'utf8')::jsonb AS doc
  FROM sboms s
  LEFT JOIN sbom_bindings sb ON sb.sbom_id = s.id
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
),
deps AS (
  SELECT
    sj.sbom_id,
    sj.asset_type,
    sj.asset_ref_id,
    d->>'ref' AS component_ref,
    array_agg(dep) FILTER (WHERE dep IS NOT NULL) AS depends_on
  FROM sbom_json sj
  LEFT JOIN LATERAL jsonb_array_elements(COALESCE(sj.doc->'dependencies', '[]'::jsonb)) AS d ON TRUE
  LEFT JOIN LATERAL jsonb_array_elements_text(COALESCE(d->'dependsOn', '[]'::jsonb)) AS dep ON TRUE
  GROUP BY sj.sbom_id, sj.asset_type, sj.asset_ref_id, d->>'ref'
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
  COALESCE(d.depends_on, ARRAY[]::text[]) AS depends_on,
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
  SELECT * FROM components
  UNION ALL
  SELECT * FROM root_component
) c
LEFT JOIN deps d
  ON d.sbom_id = c.sbom_id
  AND d.asset_type IS NOT DISTINCT FROM c.asset_type
  AND d.asset_ref_id IS NOT DISTINCT FROM c.asset_ref_id
  AND d.component_ref = c.component_ref;

CREATE UNIQUE INDEX IF NOT EXISTS ux_sbom_component_mv
  ON sbom_component_view (sbom_id, component_ref, is_root);

CREATE INDEX IF NOT EXISTS idx_sbom_component_mv_sbom
  ON sbom_component_view (sbom_id);

CREATE INDEX IF NOT EXISTS idx_sbom_component_mv_kind_name
  ON sbom_component_view (kind, package_name);
