-- De-duplicate cluster_record rows and remove `msg` from the unique key.
--
-- Problem: the original unique index included `msg` in the key, so a single
-- resource could produce 3+ live rows (INITIAL + UPDATE + EXPOSURE …). Read
-- queries filter `msg != 'DELETE'` and count all of them, producing bloated
-- counts: "3 Services named spam" when only 1 exists.
--
-- Correct model: one row per resource identity. Lifecycle transitions update
-- the single row in place — the `msg` column still records the most recent
-- event type so queries can detect DELETEs and exclude deleted resources.
--
-- Migration steps:
--   1. Drop the old unique index so the dedup DELETE can run.
--   2. Keep only the most recently-updated row per
--      (cluster_id, kind, [pod_uid+container | uid]).
--   3. Recreate the unique index without `msg`.

DROP INDEX IF EXISTS ux_cluster_record_resource;

-- Keep the row with the highest received_at per resource identity; drop
-- the rest. Tie-breaker on `id` so the query is deterministic when two
-- rows share a timestamp.
DELETE FROM cluster_record r
WHERE EXISTS (
    SELECT 1 FROM cluster_record newer
    WHERE (newer.data->>'cluster_id') = (r.data->>'cluster_id')
      AND (newer.data->>'kind')       = (r.data->>'kind')
      AND CASE WHEN newer.data->>'kind' = 'Container'
               THEN (newer.data->>'pod_uid') || '/' || (newer.data->>'container')
               ELSE COALESCE(newer.data->>'uid', '')
          END
        = CASE WHEN r.data->>'kind' = 'Container'
               THEN (r.data->>'pod_uid') || '/' || (r.data->>'container')
               ELSE COALESCE(r.data->>'uid', '')
          END
      AND (
        newer.received_at > r.received_at
        OR (newer.received_at = r.received_at AND newer.id > r.id)
      )
);

CREATE UNIQUE INDEX IF NOT EXISTS ux_cluster_record_resource
    ON cluster_record ((
        (data->>'cluster_id') || ':' || (data->>'kind') || ':' ||
        CASE WHEN data->>'kind' = 'Container'
             THEN (data->>'pod_uid') || '/' || (data->>'container')
             ELSE COALESCE(data->>'uid', '')
        END
    ))
    WHERE (data->>'cluster_id') IS NOT NULL;
