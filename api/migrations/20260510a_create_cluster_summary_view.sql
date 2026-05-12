-- cluster_summary materialised view.
--
-- ClusterSummaryHandler used to derive its row-set from the `live` CTE
-- on every request — full scan of cluster_record with jsonb extraction
-- and DISTINCT ON over per-resource identity, then per-cluster
-- aggregation. At fleet scale this dominated the request budget;
-- materialising the per-cluster aggregate flips it to a single index
-- scan + ACL filter.
--
-- The MV does NOT include the cluster_sessions liveness filter — that
-- depends on NOW() and is per-request. The handler joins
-- cluster_sessions and applies ACL on top of this MV.
--
-- Refresh hooks:
--   - CallcenterHandler triggers a debounced refresh on every ingest
--     batch that touches Container / Ingress / HTTPRoute / etc. (see
--     internal/clustersummary/refresh.go).
--   - On-demand: ClusterSummaryHandler also kicks a refresh when it
--     observes the MV is unpopulated, so the first request after a
--     fresh deploy doesn't wait for the next ingest cycle.

DROP MATERIALIZED VIEW IF EXISTS cluster_summary;

CREATE MATERIALIZED VIEW cluster_summary AS
SELECT
    cr.data->>'cluster_id'                                          AS cluster_id,
    MAX(cr.data->>'cluster')                                        AS cluster,
    MAX(cr.data->>'environment')                                    AS environment,
    COUNT(*) FILTER (
        WHERE cr.data->>'kind' = 'Container'
          AND cr.data->>'pod_phase' = 'Running'
    )                                                               AS containers,
    COUNT(DISTINCT CONCAT(
        cr.data->>'registry', '/', cr.data->>'image', '@', cr.data->>'digest'
    )) FILTER (
        WHERE cr.data->>'kind' = 'Container'
          AND cr.data->>'pod_phase' = 'Running'
          AND COALESCE(cr.data->>'digest', '') <> ''
    )                                                               AS images,
    COUNT(DISTINCT cr.data->>'namespace') FILTER (
        WHERE cr.data->>'kind' = 'Container'
          AND cr.data->>'pod_phase' = 'Running'
    )                                                               AS namespaces,
    COUNT(DISTINCT cr.data->>'uid') FILTER (
        WHERE cr.data->>'kind' IN ('Ingress','HTTPRoute','GRPCRoute','IngressRoute','IngressRouteTCP')
    )                                                               AS ingress_count,
    MAX(cr.received_at)                                             AS last_seen
FROM cluster_record cr
WHERE COALESCE(cr.data->>'msg', '') <> 'DELETE'
  AND cr.data->>'cluster_id' IS NOT NULL
GROUP BY cr.data->>'cluster_id'
WITH NO DATA;

-- Unique key for REFRESH ... CONCURRENTLY.
CREATE UNIQUE INDEX idx_cluster_summary_cluster_id
    ON cluster_summary (cluster_id);

-- The handler ORDER BYs by last_seen DESC; without an index the planner
-- still uses the unique key + sort, but for fleets with hundreds of
-- clusters the sorted index is a measurable win.
CREATE INDEX idx_cluster_summary_last_seen
    ON cluster_summary (last_seen DESC);
