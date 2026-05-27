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
-- Identity-cutover dedup: SCAM's identity migration moved cluster_id
-- from the ROR slug (e.g. "p-mot-001-ho87") to the kube-system
-- Namespace UID. During the rolling cutover the same cluster posts
-- records under BOTH cluster_ids until the older slug-keyed rows TTL
-- out — and that surfaced as two rows in /api/clusters/summary for
-- one cluster. The MV now groups on a synthesized cluster_key that
-- prefers the ROR slug (which is constant across both pre- and
-- post-cutover records: pre-cutover it sits in data->>'cluster_id',
-- post-cutover it sits in data->'ror_metadata'->>'cluster_id') so
-- both record families collapse onto one row. Per-group cluster_id is
-- the kube-system UID when any merged record carries ror_metadata
-- (the authoritative post-cutover identity), else the original
-- cluster_id — keeps downstream consumers (ACL, sessions) on the
-- UUID identity once the new agent is live.
--
-- Counts use COUNT(DISTINCT resource_identity) instead of COUNT(*) so
-- pods present under both cluster_ids during the cutover window count
-- once, not twice.
--
-- Cluster display name resolution order:
--   1. ror_metadata.cluster_name in any merged record (post-cutover
--      agents stamp this directly).
--   2. clusters.ror_cluster_name  — DB-stored ROR-bound friendly name.
--   3. clusters.ror_slug          — slug if the name isn't set.
--   4. data->>'cluster' from cluster_record, but only when it differs
--      from cluster_id — SCAM stamps `cluster` to the operator-
--      configured env var on the agent. When that var is unset SCAM
--      falls back to writing the kube-system UID into `cluster` too,
--      so the inequality guard keeps step 5 from being redundant.
--   5. cluster_id as the last-resort fallback.
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
WITH merged AS (
    SELECT
        -- Slug-preferred grouping key. Pre-cutover records had the slug
        -- as cluster_id; post-cutover records have the slug nested under
        -- ror_metadata. Either way this resolves to the same string
        -- across both record families for one logical cluster. Clusters
        -- that have never had ROR binding fall through to data->>'cluster_id'
        -- (UUID for new agents, slug for old).
        COALESCE(
            NULLIF(cr.data->'ror_metadata'->>'cluster_id', ''),
            cr.data->>'cluster_id'
        )                                                            AS cluster_key,
        cr.data,
        cr.received_at
    FROM cluster_record cr
    WHERE COALESCE(cr.data->>'msg', '') <> 'DELETE'
      AND cr.data->>'cluster_id' IS NOT NULL
)
SELECT
    -- Per-group cluster_id: prefer the kube-system UID (carried in
    -- records that include ror_metadata) over the slug. Falls back to
    -- whatever's there for clusters that never sent ror_metadata.
    COALESCE(
        (array_agg(m.data->>'cluster_id' ORDER BY (m.data->'ror_metadata' IS NOT NULL) DESC, m.received_at DESC))[1],
        MAX(m.data->>'cluster_id')
    )                                                                AS cluster_id,
    COALESCE(
        NULLIF(MAX(m.data->'ror_metadata'->>'cluster_name'), ''),
        NULLIF(MAX(c.ror_cluster_name), ''),
        NULLIF(MAX(c.ror_slug), ''),
        NULLIF(MAX(NULLIF(m.data->>'cluster', m.data->>'cluster_id')), ''),
        MAX(m.data->>'cluster_id')
    )                                                                AS cluster,
    MAX(m.data->>'environment')                                      AS environment,
    -- Container count deduped across cluster_ids — (pod_uid, container)
    -- is stable across the cutover, so the same pod under two
    -- cluster_ids counts once.
    COUNT(DISTINCT (m.data->>'pod_uid') || '/' || (m.data->>'container')) FILTER (
        WHERE m.data->>'kind' = 'Container'
          AND m.data->>'pod_phase' = 'Running'
    )                                                                AS containers,
    COUNT(DISTINCT CONCAT(
        m.data->>'registry', '/', m.data->>'image', '@', m.data->>'digest'
    )) FILTER (
        WHERE m.data->>'kind' = 'Container'
          AND m.data->>'pod_phase' = 'Running'
          AND COALESCE(m.data->>'digest', '') <> ''
    )                                                                AS images,
    COUNT(DISTINCT m.data->>'namespace') FILTER (
        WHERE m.data->>'kind' = 'Container'
          AND m.data->>'pod_phase' = 'Running'
    )                                                                AS namespaces,
    -- Ingress uid is the K8s resource UID — stable across cutover for
    -- a given Ingress object, so COUNT(DISTINCT) collapses cleanly.
    COUNT(DISTINCT m.data->>'uid') FILTER (
        WHERE m.data->>'kind' IN ('Ingress','HTTPRoute','GRPCRoute','IngressRoute','IngressRouteTCP')
    )                                                                AS ingress_count,
    MAX(m.received_at)                                               AS last_seen
FROM merged m
-- LEFT JOIN clusters on each record's raw cluster_id so both the
-- slug-keyed (pre-cutover) and UUID-keyed (post-cutover) clusters
-- rows can contribute names. MAX() above coalesces whichever side
-- carries the binding.
LEFT JOIN clusters c ON c.cluster_id = m.data->>'cluster_id'
GROUP BY m.cluster_key
WITH NO DATA;

-- Unique key for REFRESH ... CONCURRENTLY. cluster_id is post-merge
-- canonical per group, still unique across rows.
CREATE UNIQUE INDEX idx_cluster_summary_cluster_id
    ON cluster_summary (cluster_id);

-- The handler ORDER BYs by last_seen DESC; without an index the planner
-- still uses the unique key + sort, but for fleets with hundreds of
-- clusters the sorted index is a measurable win.
CREATE INDEX idx_cluster_summary_last_seen
    ON cluster_summary (last_seen DESC);
