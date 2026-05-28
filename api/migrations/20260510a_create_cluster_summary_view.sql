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
-- out — that surfaced as two rows in /api/clusters/summary for one
-- physical cluster. The MV now groups on a synthesized cluster_key
-- that prefers the ROR slug — constant across both record families
-- (pre-cutover it sits in data->>'cluster_id', post-cutover in
-- data->'ror_metadata'->>'cluster_id') — so both families collapse
-- onto one row.
--
-- Identity surfaces (clean separation, replaces the previous combined
-- `cluster` column whose value depended on which records existed):
--
--   cluster_id        Per-group canonical identifier. Prefers the
--                     kube-system UID when any merged record carries
--                     ror_metadata (the authoritative post-cutover
--                     stamp); else the original raw cluster_id (slug
--                     for clusters that have never cut over).
--
--   cluster_name      The agent's env-var-configured display label
--                     (SCAM stamps it into `data->>'cluster'`). NULL
--                     when the env var is unset and SCAM falls back to
--                     duplicating cluster_id into `cluster` — the
--                     NULLIF on the inequality keeps the field
--                     meaningful instead of repeating cluster_id.
--
--   ror_slug          ROR slug (data->'ror_metadata'->>'cluster_id').
--                     NULL when no merged record carried ror_metadata.
--   ror_cluster_name  ROR-side friendly name. NULL when missing.
--   ror_env           ROR-side environment string. NULL when missing.
--
-- The handler nests {slug, cluster_name, env} into a `ror_metadata`
-- object on the wire — its presence/absence is the single source of
-- truth for "did this cluster send ROR metadata, or is it on env-var
-- fallback?" The frontend chooses display name as
-- ror_metadata.cluster_name → cluster_name → cluster_id.
--
-- Counts use COUNT(DISTINCT resource_identity) instead of COUNT(*) so
-- pods present under both cluster_ids during the cutover window count
-- once, not twice.
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
        -- ror_metadata. Either path resolves to the same string across
        -- both record families for one logical cluster. Clusters that
        -- have never had ROR binding fall through to data->>'cluster_id'
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
    -- Env-var label only; NULLIF strips the case where SCAM stamped
    -- cluster_id into `cluster` too. NULL when no record has a distinct
    -- env-var value.
    NULLIF(MAX(NULLIF(m.data->>'cluster', m.data->>'cluster_id')), '')
                                                                     AS cluster_name,
    -- ROR triple. All-or-nothing per logical cluster: if any record
    -- has ror_metadata, every column has its piece; otherwise all
    -- three are NULL. MAX(...) collapses across records — they
    -- should agree for the same cluster, so picking any is safe.
    NULLIF(MAX(m.data->'ror_metadata'->>'cluster_id'), '')           AS ror_slug,
    NULLIF(MAX(m.data->'ror_metadata'->>'cluster_name'), '')         AS ror_cluster_name,
    NULLIF(MAX(m.data->'ror_metadata'->>'env'), '')                  AS ror_env,
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
GROUP BY m.cluster_key
WITH NO DATA;

-- Unique key for REFRESH ... CONCURRENTLY. cluster_id is post-merge
-- canonical per group, still unique across rows.
CREATE UNIQUE INDEX idx_cluster_summary_cluster_id
    ON cluster_summary (cluster_id);

-- The handler ORDER BYs by last_seen DESC; the sorted index is a
-- measurable win on fleets with hundreds of clusters.
CREATE INDEX idx_cluster_summary_last_seen
    ON cluster_summary (last_seen DESC);

-- Search hits on the env-var name and ROR fields; partial indexes skip
-- rows where the column is NULL (common for cluster_name on small
-- fleets that don't set SPAM_CLUSTER, and for the ROR columns until
-- the binding lands).
CREATE INDEX idx_cluster_summary_cluster_name
    ON cluster_summary (cluster_name) WHERE cluster_name IS NOT NULL;
CREATE INDEX idx_cluster_summary_ror_slug
    ON cluster_summary (ror_slug) WHERE ror_slug IS NOT NULL;
