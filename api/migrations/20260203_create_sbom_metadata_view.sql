DROP MATERIALIZED VIEW IF EXISTS sbom_metadata_view;
DROP VIEW IF EXISTS sbom_metadata_view;

CREATE MATERIALIZED VIEW sbom_metadata_view AS
WITH sbom_json AS (
  SELECT
    s.id AS sbom_id,
    s.format,
    s.created_at,
    s.ingested_by_user_id,
    sb.asset_type,
    sb.asset_ref_id,
    convert_from(s.content_bytes, 'utf8')::jsonb AS doc
  FROM sboms s
  LEFT JOIN sbom_bindings sb ON sb.sbom_id = s.id
),
scanner AS (
  SELECT
    sj.sbom_id,
    t->>'name' AS scanner_name,
    t->>'version' AS scanner_version
  FROM sbom_json sj
  LEFT JOIN LATERAL jsonb_array_elements(
    COALESCE(sj.doc->'metadata'->'tools'->'components', '[]'::jsonb)
  ) AS t ON TRUE
),
root_component AS (
  SELECT
    sj.sbom_id,
    sj.doc->'metadata'->'component'->>'bom-ref' AS root_ref,
    sj.doc->'metadata'->'component'->>'name' AS root_name,
    sj.doc->'metadata'->'component'->>'type' AS root_type
  FROM sbom_json sj
),
repo_bindings AS (
  SELECT
    sb.sbom_id,
    r.id AS repo_id,
    r.org || '/' || r.slug AS repo_name,
    rc.id AS repo_commit_id,
    rc.commit_sha AS commit_sha
  FROM sbom_bindings sb
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
  FROM sbom_bindings sb
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
LEFT JOIN repo_bindings rc ON rc.sbom_id = sj.sbom_id
LEFT JOIN image_bindings ib ON ib.sbom_id = sj.sbom_id
WITH NO DATA;

CREATE UNIQUE INDEX IF NOT EXISTS ux_sbom_metadata_mv
  ON sbom_metadata_view (sbom_id);

CREATE INDEX IF NOT EXISTS idx_sbom_metadata_mv_repo
  ON sbom_metadata_view (repo_id);

CREATE INDEX IF NOT EXISTS idx_sbom_metadata_mv_image
  ON sbom_metadata_view (image_id);
