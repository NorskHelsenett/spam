-- Expression indexes for efficient JSONB field queries on cluster_record.
CREATE INDEX IF NOT EXISTS idx_cluster_record_kind
    ON cluster_record ((data->>'kind'));

CREATE INDEX IF NOT EXISTS idx_cluster_record_cluster_id
    ON cluster_record ((data->>'cluster_id'));

-- Upsert key: unique per resource + event type within a cluster.
-- Includes msg so we keep one row per lifecycle event (INITIAL, UPDATE, DELETE).
-- Containers use pod_uid/container, everything else uses uid.
CREATE UNIQUE INDEX IF NOT EXISTS ux_cluster_record_resource
    ON cluster_record ((
        (data->>'cluster_id') || ':' || (data->>'kind') || ':' || (data->>'msg') || ':' ||
        CASE WHEN data->>'kind' = 'Container'
             THEN (data->>'pod_uid') || '/' || (data->>'container')
             ELSE COALESCE(data->>'uid', '')
        END
    ))
    WHERE (data->>'cluster_id') IS NOT NULL;
