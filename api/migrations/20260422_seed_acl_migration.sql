-- Seed grandfathered access so Phase 2 deployment doesn't change
-- behavior until handlers are wired in Phase 3.
--
-- Only one grant is seeded: global_reader → every repo (wildcard
-- pattern). That preserves today's "global_reader sees all private
-- repos" behavior without enumerating rows, and lets admins later
-- revoke the single row to flip private-by-default on.
--
-- NOTE: no cluster grant is seeded. This is a deliberate behavior
-- change — today's global_reader sees clusters; after Phase 3 ships
-- they will not until an admin grants access. That's the whole point
-- of introducing the `clusters` entity.
--
-- The `source = 'migration'` tag lets the admin UI (Phase 4) produce a
-- "review grandfathered grants" report without touching explicit or
-- ingest_default rows.
--
-- Idempotent: WHERE NOT EXISTS guards against duplicate inserts if
-- EnsureViews re-runs the file.

INSERT INTO acl_grants (id, subject_type, subject_id, scope_type, scope_pattern, action, source, created_at)
SELECT
    gen_random_uuid()::text,
    'group',
    'global_reader',
    'repo',
    '{}'::jsonb,
    'read',
    'migration',
    NOW()
WHERE NOT EXISTS (
    SELECT 1 FROM acl_grants
    WHERE subject_type = 'group'
      AND subject_id   = 'global_reader'
      AND scope_type   = 'repo'
      AND scope_pattern = '{}'::jsonb
      AND source       = 'migration'
);

-- Backfill the clusters table from every distinct cluster_id already
-- observed in cluster_record. DisplayName falls back to the cluster_id
-- when the agent didn't report a friendly `cluster` field.
INSERT INTO clusters (id, cluster_id, display_name, first_seen_at, created_at)
SELECT
    gen_random_uuid()::text AS id,
    cluster_id,
    display_name,
    first_seen_at,
    NOW() AS created_at
FROM (
    SELECT
        data->>'cluster_id' AS cluster_id,
        COALESCE(NULLIF(data->>'cluster', ''), data->>'cluster_id') AS display_name,
        MIN(received_at) AS first_seen_at
    FROM cluster_record
    WHERE data->>'cluster_id' IS NOT NULL
      AND data->>'cluster_id' <> ''
    GROUP BY data->>'cluster_id', COALESCE(NULLIF(data->>'cluster', ''), data->>'cluster_id')
) seen
ON CONFLICT (cluster_id) DO NOTHING;
