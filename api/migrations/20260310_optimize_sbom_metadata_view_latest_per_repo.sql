-- Optimize sbom_metadata_view to only materialize the latest SBOM per repo,
-- matching the sbom_component_view optimization. Also replaces expression-based
-- unique indexes (COALESCE) with plain column indexes required for CONCURRENTLY refresh.

DROP MATERIALIZED VIEW IF EXISTS sbom_metadata_view;

CREATE MATERIALIZED VIEW sbom_metadata_view AS
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
sbom_docs AS (
  SELECT
    s.id AS sbom_id,
    s.format,
    s.created_at,
    s.ingested_by_user_id,
    convert_from(s.content_bytes, 'utf8')::jsonb AS doc
  FROM sboms s
  WHERE s.id IN (SELECT sbom_id FROM latest_bindings)
),
sbom_json AS (
  SELECT
    sd.sbom_id,
    sd.format,
    sd.created_at,
    sd.ingested_by_user_id,
    lb.asset_type,
    lb.asset_ref_id,
    sd.doc
  FROM sbom_docs sd
  JOIN latest_bindings lb ON lb.sbom_id = sd.sbom_id
),
scanner AS (
  SELECT
    sd.sbom_id,
    COALESCE(
      string_agg(DISTINCT t->>'name', ', ') FILTER (WHERE t->>'name' IS NOT NULL AND t->>'name' <> ''),
      ''
    ) AS scanner_name,
    COALESCE(
      string_agg(DISTINCT t->>'version', ', ') FILTER (WHERE t->>'version' IS NOT NULL AND t->>'version' <> ''),
      ''
    ) AS scanner_version
  FROM sbom_docs sd
  LEFT JOIN LATERAL jsonb_array_elements(
    COALESCE(sd.doc->'metadata'->'tools'->'components', '[]'::jsonb)
  ) AS t ON TRUE
  GROUP BY sd.sbom_id
),
root_component AS (
  SELECT
    sd.sbom_id,
    sd.doc->'metadata'->'component'->>'bom-ref' AS root_ref,
    sd.doc->'metadata'->'component'->>'name' AS root_name,
    sd.doc->'metadata'->'component'->>'type' AS root_type
  FROM sbom_docs sd
  WHERE sd.doc->'metadata'->'component' IS NOT NULL
),
repo_bindings AS (
  SELECT
    sb.sbom_id,
    r.id AS repo_id,
    r.org || '/' || r.slug AS repo_name,
    rc.id AS repo_commit_id,
    rc.commit_sha AS commit_sha
  FROM latest_bindings sb
  JOIN repo_commits rc ON rc.id = sb.asset_ref_id
  JOIN repos r ON r.id = rc.repo_id
  WHERE sb.asset_type = 'REPO_COMMIT'
),
image_bindings AS (
  SELECT
    sb.sbom_id,
    id.id AS image_id,
    id.digest AS image_digest,
    id.registry AS image_registry,
    id.repository AS image_repository
  FROM latest_bindings sb
  JOIN image_digests id ON id.id = sb.asset_ref_id
  WHERE sb.asset_type = 'IMAGE_DIGEST'
)
SELECT
  sj.sbom_id,
  sj.format,
  sj.created_at,
  sj.ingested_by_user_id,
  sj.asset_type,
  sj.asset_ref_id,
  COALESCE(sc.scanner_name, '') AS scanner_name,
  COALESCE(sc.scanner_version, '') AS scanner_version,
  rc.repo_id,
  rc.repo_name,
  rc.repo_commit_id,
  rc.commit_sha,
  ib.image_id,
  ib.image_digest,
  ib.image_registry,
  ib.image_repository,
  r.root_ref,
  r.root_name,
  r.root_type
FROM sbom_json sj
LEFT JOIN scanner sc ON sc.sbom_id = sj.sbom_id
LEFT JOIN root_component r ON r.sbom_id = sj.sbom_id
LEFT JOIN repo_bindings rc ON rc.sbom_id = sj.sbom_id AND rc.repo_commit_id = sj.asset_ref_id
LEFT JOIN image_bindings ib ON ib.sbom_id = sj.sbom_id AND ib.image_id = sj.asset_ref_id
WITH NO DATA;

-- Plain column unique index (no expressions) required for CONCURRENTLY refresh.
-- asset_type and asset_ref_id are NOT NULL because we use INNER JOIN on latest_bindings.
CREATE UNIQUE INDEX IF NOT EXISTS ux_sbom_metadata_mv
  ON sbom_metadata_view (sbom_id, asset_type, asset_ref_id);

CREATE INDEX IF NOT EXISTS idx_sbom_metadata_mv_repo
  ON sbom_metadata_view (repo_id);

CREATE INDEX IF NOT EXISTS idx_sbom_metadata_mv_image
  ON sbom_metadata_view (image_id);
