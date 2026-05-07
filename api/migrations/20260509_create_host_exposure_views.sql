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
-- Every jsonb_array_elements* call below uses
--     CASE jsonb_typeof(...) WHEN 'array' THEN ... ELSE '[]'::jsonb END
-- instead of plain COALESCE. COALESCE only handles SQL NULL, not jsonb
-- scalars — so a malformed cluster_record row with e.g. rules=null (the
-- JSON literal, not SQL NULL) or rules="" would crash the entire
-- REFRESH with SQLSTATE 22023 ("cannot extract elements from a scalar")
-- instead of just contributing zero rows. Guarding by jsonb_typeof
-- isolates bad records.

DROP MATERIALIZED VIEW IF EXISTS exposed_digests;
DROP MATERIALIZED VIEW IF EXISTS host_exposure;

CREATE MATERIALIZED VIEW host_exposure AS
WITH per_rule_backend AS (
    -- k8s Ingress: one row per (Ingress object, rule.host, rule.path.backend_name).
    -- Multiple rules / paths within the same Ingress for the same host
    -- collapse at the GROUP BY below — the per-backend grain here lets
    -- us dedupe individual backend names cleanly.
    SELECT
        cr.data->>'cluster_id'                AS cluster_id,
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
    cluster_id,
    MAX(cluster)                                                 AS cluster,
    namespace,
    MAX(environment)                                             AS environment,
    host,
    kind,
    name,
    BOOL_OR(tls)                                                 AS tls,
    COALESCE(MAX(NULLIF(lb_ips, '')), '')                        AS lb_ips,
    COALESCE(MAX(NULLIF(ingress_class, '')), '')                 AS ingress_class,
    COALESCE(
        string_agg(DISTINCT backend, ', ' ORDER BY backend)
            FILTER (WHERE backend IS NOT NULL),
        ''
    )                                                            AS backends,
    MAX(last_seen)                                               AS last_seen
FROM per_rule_backend
GROUP BY cluster_id, namespace, host, kind, name
WITH NO DATA;

-- Unique key for REFRESH ... CONCURRENTLY. Also the natural lookup
-- key from the chain drawer (host + cluster + namespace + kind + name).
CREATE UNIQUE INDEX idx_host_exposure_unique
    ON host_exposure (cluster_id, namespace, host, kind, name);

-- Hot lookup paths.
CREATE INDEX idx_host_exposure_cluster
    ON host_exposure (cluster_id);
CREATE INDEX idx_host_exposure_host
    ON host_exposure (host);


CREATE MATERIALIZED VIEW exposed_digests AS
-- For each host_exposure row, walk backends → Service (by name in same
-- cluster/namespace) → Container (by selector match) → digest. Mirrors
-- the chain that asset_risk's two UNIONed CTEs used to compute
-- inline; consolidating it here means triage and the hosts list
-- share one materialised projection.
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
 AND svc.data->>'cluster_id'             = he.cluster_id
 AND svc.data->>'namespace'              = he.namespace
 AND svc.data->>'name'                   = be.name
JOIN cluster_record cont
  ON cont.data->>'kind'                  = 'Container'
 AND COALESCE(cont.data->>'msg','')      <> 'DELETE'
 AND cont.data->>'cluster_id'            = svc.data->>'cluster_id'
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
