-- cluster_image_inventory: per running container, projected from
-- cluster_record. Drives /api/clusters/registry-distribution and
-- /api/clusters/images/detail, which previously re-scanned the full
-- cluster_record + DISTINCT ON + jsonb extraction on every request.
--
-- The grain is per-container (one row per Container record). Read-side
-- aggregations group by (registry, image, digest) to count clusters,
-- namespaces, and pods — the per-row grain is what lets ACL on
-- cluster_id work as a WHERE before the GROUP BY.
--
-- Refresh is driven by the same CallcenterHandler hook as
-- cluster_summary: any Container ingest triggers a debounced refresh
-- through the clustersummary gate. Both MVs share the same data source
-- and freshness contract, so coalescing the refreshes is cheap.
--
-- jsonb extraction happens once at refresh time; the read path joins
-- plain text/timestamp columns with proper indexes.

DROP MATERIALIZED VIEW IF EXISTS cluster_image_inventory;

CREATE MATERIALIZED VIEW cluster_image_inventory AS
SELECT
    cr.id                                                       AS record_id,
    cr.data->>'cluster_id'                                      AS cluster_id,
    cr.data->>'namespace'                                       AS namespace,
    cr.data->>'registry'                                        AS raw_registry,
    COALESCE(NULLIF(cr.data->>'registry', ''), 'Docker Hub')    AS registry,
    cr.data->>'image'                                           AS image,
    cr.data->>'digest'                                          AS digest,
    NULLIF(cr.data->>'tag', '')                                 AS tag,
    cr.received_at                                              AS last_seen
FROM cluster_record cr
WHERE cr.data->>'kind' = 'Container'
  AND cr.data->>'pod_phase' = 'Running'
  AND COALESCE(cr.data->>'msg', '') <> 'DELETE'
  AND COALESCE(cr.data->>'digest', '') <> ''
  AND cr.data->>'cluster_id' IS NOT NULL
WITH NO DATA;

-- Unique key for REFRESH ... CONCURRENTLY. record_id is unique in
-- cluster_record (uuid primary key), so it's a perfect dedup key.
CREATE UNIQUE INDEX idx_cluster_image_inventory_record_id
    ON cluster_image_inventory (record_id);

-- Aggregation key — every read path GROUPs BY this tuple, so a
-- multi-column btree gives the planner a sorted scan path. raw_registry
-- (not the COALESCEd "Docker Hub" alias) is the join key into
-- image_digests.registry, so it's first.
CREATE INDEX idx_cluster_image_inventory_image
    ON cluster_image_inventory (raw_registry, image, digest);

-- ACL gate column — clusterACLFilter narrows by cluster_id.
CREATE INDEX idx_cluster_image_inventory_cluster
    ON cluster_image_inventory (cluster_id);

-- registry-distribution groups by the display-registry; partial scan
-- helps the donut endpoint.
CREATE INDEX idx_cluster_image_inventory_registry
    ON cluster_image_inventory (registry);
