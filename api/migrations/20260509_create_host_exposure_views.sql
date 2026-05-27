-- host_exposure / exposed_digests: split the SCAM ingress projection
-- into two materialized views so the hosts list and triage's
-- internet_exposed predicate stop re-deriving the same Ingress →
-- Service → Container chain on every read.
--
--   host_exposure   one row per (cluster_id, namespace, host, kind,
--                   name) — slow-changing URL-level metadata. Drives
--                   /api/clusters/hosts.
--
--   exposed_digests one row per (host_exposure key, digest) — the
--                   high-churn projection that captures which images
--                   sit on a publicly-served path. Drives the hosts
--                   list's per-host workload count AND replaces the
--                   two UNIONed CTEs in asset_risk.
--
-- Both views are created WITH NO DATA and refreshed CONCURRENTLY
-- thereafter under a dedicated advisory lock (see
-- internal/db/host_exposure_view.go). Refresh ordering matters:
-- exposed_digests reads from host_exposure, so host_exposure must
-- refresh first.
--
-- Identity-cutover dedup: SCAM's identity migration moved cluster_id
-- from the ROR slug to the kube-system Namespace UID. During the
-- rolling cutover the same Ingress / HTTPRoute / etc. posts records
-- under both cluster_ids until the older slug-keyed rows TTL out, so
-- /api/clusters/hosts saw the same host listed twice — one row keyed
-- by UID, one by slug.
--
-- The fix mirrors cluster_summary: the per_rule_backend CTE projects
-- a cluster_key derived from COALESCE(ror_metadata.cluster_id,
-- cluster_id) — the ROR slug is constant across both record families,
-- so pre- and post-cutover Ingress records collapse onto one
-- host_exposure row. The exposed cluster_id is the kube-system UID
-- whenever any merged record carries ror_metadata (the authoritative
-- post-cutover stamp).
--
-- exposed_digests then joins Services and Containers using the same
-- cluster_key — so a post-cutover Ingress is correctly chained to
-- pre-cutover Service / Container records during the brief
-- pre-TTL window. idx_cluster_record_cluster_key (created below)
-- backs that join with an expression index so the JOIN doesn't
-- regress to a seq scan.
--
-- Every jsonb_array_elements* call below uses
--     CASE jsonb_typeof(...) WHEN 'array' THEN ... ELSE '[]'::jsonb END
-- instead of plain COALESCE. COALESCE only handles SQL NULL, not jsonb
-- scalars — so a malformed cluster_record row with e.g. rules=null (the
-- JSON literal, not SQL NULL) or rules="" would crash the entire
-- REFRESH with SQLSTATE 22023 ("cannot extract elements from a scalar")
-- instead of just contributing zero rows. Guarding by jsonb_typeof
-- isolates bad records.

-- CASCADE because asset_risk (created by 20260509a) holds a dependency
-- on exposed_digests via its `exposed_clusters` CTE. Without CASCADE,
-- DROP errors with SQLSTATE 2BP01 the moment anyone bumps this
-- migration's hash. asset_risk gets recreated by 20260509a + 20260510b
-- in the same EnsureViews pass; both files carry hash-bump comments
-- documenting the chained recreate.
DROP MATERIALIZED VIEW IF EXISTS exposed_digests CASCADE;
DROP MATERIALIZED VIEW IF EXISTS host_exposure CASCADE;

-- Expression index for the cluster_key join used in exposed_digests
-- (and by host_exposure's per_rule_backend stage). Without it the
-- Service / Container lookups regress to a seq scan over cluster_record
-- because the existing idx_cluster_record_cluster_id covers only the
-- raw column.
CREATE INDEX IF NOT EXISTS idx_cluster_record_cluster_key
    ON cluster_record ((
        COALESCE(NULLIF(data->'ror_metadata'->>'cluster_id',''), data->>'cluster_id')
    ));

CREATE MATERIALIZED VIEW host_exposure AS
WITH per_rule_backend AS (
    -- k8s Ingress: one row per (Ingress object, rule.host, rule.path.backend_name).
    -- Multiple rules / paths within the same Ingress for the same host
    -- collapse at the GROUP BY below — the per-backend grain here lets
    -- us dedupe individual backend names cleanly.
    SELECT
        cr.data->>'cluster_id'                AS cluster_id,
        COALESCE(
            NULLIF(cr.data->'ror_metadata'->>'cluster_id', ''),
            cr.data->>'cluster_id'
        )                                     AS cluster_key,
        cr.data->'ror_metadata'->>'cluster_name' AS ror_cluster_name,
        COALESCE(cr.data->>'cluster','')      AS cluster,
        cr.data->>'namespace'                 AS namespace,
        COALESCE(cr.data->>'environment','')  AS environment,
        r->>'host'                            AS host,
        'Ingress'::text                       AS kind,
        cr.data->>'name'                      AS name,
        NULLIF(p->>'backend_name','')         AS backend,
        jsonb_typeof(cr.data->'tls') = 'array'
            AND jsonb_array_length(COALESCE(cr.data->'tls','[]'::jsonb)) > 0
                                              AS tls,
        CASE WHEN jsonb_typeof(cr.data->'lb_ips') = 'array'
            THEN COALESCE((SELECT string_agg(ip, ', ')
                             FROM jsonb_array_elements_text(cr.data->'lb_ips') AS ip), '')
            ELSE '' END                       AS lb_ips,
        COALESCE(cr.data->>'ingress_class','') AS ingress_class,
        cr.received_at                        AS last_seen
    FROM cluster_record cr
    CROSS JOIN LATERAL jsonb_array_elements(CASE jsonb_typeof(cr.data->'rules') WHEN 'array' THEN cr.data->'rules' ELSE '[]'::jsonb END) AS r
    LEFT  JOIN LATERAL jsonb_array_elements(CASE jsonb_typeof(r->'paths') WHEN 'array' THEN r->'paths' ELSE '[]'::jsonb END)      AS p ON TRUE
    WHERE cr.data->>'kind' = 'Ingress'
      AND COALESCE(cr.data->>'msg','') <> 'DELETE'
      AND NULLIF(r->>'host','') IS NOT NULL

    UNION ALL

    -- Gateway API: HTTPRoute / GRPCRoute / TLSRoute. backends are
    -- stored as data.backends[].name; hostnames live in data.hostnames[].
    SELECT
        cr.data->>'cluster_id',
        COALESCE(
            NULLIF(cr.data->'ror_metadata'->>'cluster_id', ''),
            cr.data->>'cluster_id'
        ),
        cr.data->'ror_metadata'->>'cluster_name',
        COALESCE(cr.data->>'cluster',''),
        cr.data->>'namespace',
        COALESCE(cr.data->>'environment',''),
        h,
        cr.data->>'kind',
        cr.data->>'name',
        NULLIF(b->>'name',''),
        FALSE,
        '',
        '',
        cr.received_at
    FROM cluster_record cr
    CROSS JOIN LATERAL jsonb_array_elements_text(CASE jsonb_typeof(cr.data->'hostnames') WHEN 'array' THEN cr.data->'hostnames' ELSE '[]'::jsonb END) AS h
    LEFT  JOIN LATERAL jsonb_array_elements(CASE jsonb_typeof(cr.data->'backends') WHEN 'array' THEN cr.data->'backends' ELSE '[]'::jsonb END)       AS b ON TRUE
    WHERE cr.data->>'kind' IN ('HTTPRoute','GRPCRoute','TLSRoute')
      AND COALESCE(cr.data->>'msg','') <> 'DELETE'
      AND NULLIF(h,'') IS NOT NULL

    UNION ALL

    -- Traefik IngressRoute / IngressRouteTCP. tls is implied by a
    -- non-empty tls_secret; backends are data.backends[].name.
    SELECT
        cr.data->>'cluster_id',
        COALESCE(
            NULLIF(cr.data->'ror_metadata'->>'cluster_id', ''),
            cr.data->>'cluster_id'
        ),
        cr.data->'ror_metadata'->>'cluster_name',
        COALESCE(cr.data->>'cluster',''),
        cr.data->>'namespace',
        COALESCE(cr.data->>'environment',''),
        h,
        cr.data->>'kind',
        cr.data->>'name',
        NULLIF(b->>'name',''),
        COALESCE(cr.data->>'tls_secret','') <> '',
        '',
        '',
        cr.received_at
    FROM cluster_record cr
    CROSS JOIN LATERAL jsonb_array_elements_text(CASE jsonb_typeof(cr.data->'hosts') WHEN 'array' THEN cr.data->'hosts' ELSE '[]'::jsonb END)    AS h
    LEFT  JOIN LATERAL jsonb_array_elements(CASE jsonb_typeof(cr.data->'backends') WHEN 'array' THEN cr.data->'backends' ELSE '[]'::jsonb END)      AS b ON TRUE
    WHERE cr.data->>'kind' IN ('IngressRoute','IngressRouteTCP')
      AND COALESCE(cr.data->>'msg','') <> 'DELETE'
      AND NULLIF(h,'') IS NOT NULL
)
SELECT
    -- Per-group canonical cluster_id. Prefer the UID-stamped variant
    -- from records carrying ror_metadata; fall back to whatever raw
    -- cluster_id we saw for clusters that never sent ror_metadata.
    COALESCE(
        (array_agg(prb.cluster_id ORDER BY (prb.ror_cluster_name IS NOT NULL) DESC, prb.last_seen DESC))[1],
        MAX(prb.cluster_id)
    )                                                            AS cluster_id,
    -- cluster_key is the merge axis — exposed_digests joins
    -- Service / Container records against it via the expression index
    -- so pre-cutover svc/cont records still chain into a post-cutover
    -- Ingress (and vice versa).
    prb.cluster_key                                              AS cluster_key,
    -- Cluster display name resolution order:
    --   1. ror_metadata.cluster_name on any merged record (post-
    --      cutover agents stamp this directly).
    --   2. clusters.ror_cluster_name — DB-stored ROR-bound name.
    --   3. clusters.ror_slug         — slug fallback.
    --   4. prb.cluster (env-var label) when distinct from the raw
    --      cluster_id (SCAM stamps `cluster` to operator-configured
    --      env var; absent that, it duplicates cluster_id which we
    --      then NULLIF away to keep step 5 from being redundant).
    --   5. cluster_id final fallback.
    COALESCE(
        NULLIF(MAX(prb.ror_cluster_name), ''),
        NULLIF(MAX(c.ror_cluster_name), ''),
        NULLIF(MAX(c.ror_slug), ''),
        NULLIF(MAX(NULLIF(prb.cluster, prb.cluster_id)), ''),
        MAX(prb.cluster_id)
    )                                                            AS cluster,
    prb.namespace,
    MAX(prb.environment)                                         AS environment,
    prb.host,
    prb.kind,
    prb.name,
    BOOL_OR(prb.tls)                                             AS tls,
    COALESCE(MAX(NULLIF(prb.lb_ips, '')), '')                    AS lb_ips,
    COALESCE(MAX(NULLIF(prb.ingress_class, '')), '')             AS ingress_class,
    COALESCE(
        string_agg(DISTINCT prb.backend, ', ' ORDER BY prb.backend)
            FILTER (WHERE prb.backend IS NOT NULL),
        ''
    )                                                            AS backends,
    MAX(prb.last_seen)                                           AS last_seen
FROM per_rule_backend prb
-- LEFT JOIN clusters on the raw per-record cluster_id so both slug-
-- keyed (pre-cutover) and UID-keyed (post-cutover) clusters rows can
-- contribute names; MAX() above coalesces whichever side carries the
-- binding.
LEFT JOIN clusters c ON c.cluster_id = prb.cluster_id
GROUP BY prb.cluster_key, prb.namespace, prb.host, prb.kind, prb.name
WITH NO DATA;

-- Unique key for REFRESH ... CONCURRENTLY. cluster_id is post-merge
-- canonical per group, so still unique across rows.
CREATE UNIQUE INDEX idx_host_exposure_unique
    ON host_exposure (cluster_id, namespace, host, kind, name);

-- Hot lookup paths.
CREATE INDEX idx_host_exposure_cluster
    ON host_exposure (cluster_id);
CREATE INDEX idx_host_exposure_host
    ON host_exposure (host);
-- cluster_key index supports exposed_digests' join below and any
-- downstream readers that want to find host_exposure rows for a
-- ROR slug directly.
CREATE INDEX idx_host_exposure_cluster_key
    ON host_exposure (cluster_key);


CREATE MATERIALIZED VIEW exposed_digests AS
-- For each host_exposure row, walk backends → Service (by name in same
-- cluster/namespace) → Container (by selector match) → digest. Mirrors
-- the chain that asset_risk's two UNIONed CTEs used to compute
-- inline; consolidating it here means triage and the hosts list
-- share one materialised projection.
--
-- The svc / cont joins match on cluster_key (the slug-preferred merge
-- axis) so pre-cutover Service / Container records still chain into a
-- post-cutover Ingress while both record families coexist during
-- the identity rollout. idx_cluster_record_cluster_key backs the
-- COALESCE expression as an index lookup.
SELECT DISTINCT
    he.cluster_id,
    he.namespace,
    he.host,
    he.kind                              AS exposure_kind,
    he.name                              AS exposure_name,
    cont.data->>'digest'                 AS digest
FROM host_exposure he
CROSS JOIN LATERAL unnest(string_to_array(NULLIF(he.backends,''), ', ')) AS be(name)
JOIN cluster_record svc
  ON svc.data->>'kind'                   = 'Service'
 AND COALESCE(svc.data->>'msg','')       <> 'DELETE'
 AND COALESCE(NULLIF(svc.data->'ror_metadata'->>'cluster_id',''), svc.data->>'cluster_id')
                                         = he.cluster_key
 AND svc.data->>'namespace'              = he.namespace
 AND svc.data->>'name'                   = be.name
JOIN cluster_record cont
  ON cont.data->>'kind'                  = 'Container'
 AND COALESCE(cont.data->>'msg','')      <> 'DELETE'
 AND COALESCE(NULLIF(cont.data->'ror_metadata'->>'cluster_id',''), cont.data->>'cluster_id')
                                         = COALESCE(NULLIF(svc.data->'ror_metadata'->>'cluster_id',''), svc.data->>'cluster_id')
 AND cont.data->>'namespace'             = svc.data->>'namespace'
 AND (cont.data->'pod_labels')           @> (svc.data->'selector')
 AND COALESCE(cont.data->>'digest','')   <> ''
WITH NO DATA;

-- Unique key for REFRESH ... CONCURRENTLY.
CREATE UNIQUE INDEX idx_exposed_digests_unique
    ON exposed_digests (cluster_id, namespace, host, exposure_kind, exposure_name, digest);

-- asset_risk reads (digest) and (cluster_id) — keep both indexed.
CREATE INDEX idx_exposed_digests_digest
    ON exposed_digests (digest);
CREATE INDEX idx_exposed_digests_cluster
    ON exposed_digests (cluster_id);

-- Hosts list joins (cluster_id, namespace, host, exposure_kind,
-- exposure_name) for the per-host workload aggregate; the unique
-- index above covers it as a leftmost-prefix scan.
