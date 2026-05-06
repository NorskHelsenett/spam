-- asset_risk: per-asset triage signals materialized into one row per
-- (asset_type, asset_id) so the /api/triage handler can rank repos /
-- images / clusters by composite Threat & Trust without re-running the
-- heavy joins on every page load. Modeled on the unified vuln MVs
-- introduced in 20260430_create_materialized_unified_vuln_views.sql:
-- created WITH NO DATA, populated asynchronously at boot, refreshed
-- CONCURRENTLY thereafter under an advisory lock.
--
-- Threat columns are "this asset has acute issues right now":
--   critical_count, high_count       — severity-bucketed vuln counts
--   kev_count                        — vulns listed in CISA KEV
--   epss_max                         — worst EPSS score across vulns
--   active_secret_count              — gitleaks findings whose secret
--                                      hash matched a probe row with
--                                      status='valid' (i.e. confirmed
--                                      live credentials, not noise)
--   internet_exposed                 — image runs in a workload that's
--                                      reachable via the cluster's
--                                      Ingress/HTTPRoute chain
--
-- Trust columns are "how confident are we in this asset's chain of
-- custody":
--   signed_commits_pct               — % of recent commits with a good
--                                      git signature (%G? = 'G')
--   image_signed                     — verified_source flag (always
--                                      false today; Phase 2 wires
--                                      cosign verify properly)
--   scan_age_days                    — days since the most recent scan
--   has_sbom                         — SBOM exists for this asset
--
-- Cluster threat numbers roll up from the images running in the
-- cluster: cluster_record(kind=Container, digest) → image_digests →
-- view_unified_image_vulnerabilities. We can do this rollup honestly
-- in Phase 1 because the cluster→image binding (k8s-observed digest)
-- is a fact we own. Trusting that the *observed* digest matches what
-- was *built* from a given commit requires signing and is Phase 2.

CREATE EXTENSION IF NOT EXISTS pgcrypto;

DROP MATERIALIZED VIEW IF EXISTS asset_risk;

CREATE MATERIALIZED VIEW asset_risk AS
WITH
-- ---------- chain: digest → internet-exposed? ----------
-- A digest is internet-exposed when there exists in the same cluster
-- and namespace: a Container record with that digest, a Service whose
-- selector matches the Container's pod_labels, and an Ingress/HTTPRoute
-- whose rules[].paths[].backend_name equals that Service's name. This
-- mirrors HostChainHandler's traversal in scam/handler.go but as a
-- bulk SET-returning query the MV refresh can run in one shot.
--
-- IngressRoute (Traefik CRD) and Gateway/GRPCRoute are not yet covered
-- by this chain — they store backend refs in different JSONB shapes.
-- Phase 2 work to widen the union.
exposed_digests AS (
    SELECT DISTINCT
        cont.data->>'digest'     AS digest,
        cont.data->>'cluster_id' AS cluster_id
    FROM cluster_record ing
    JOIN cluster_record svc
      ON svc.data->>'kind'       = 'Service'
     AND svc.data->>'cluster_id' = ing.data->>'cluster_id'
     AND svc.data->>'namespace'  = ing.data->>'namespace'
     AND EXISTS (
         SELECT 1
           FROM jsonb_array_elements(ing.data->'rules') AS r,
                jsonb_array_elements(r->'paths')        AS p
          WHERE p->>'backend_name' = svc.data->>'name'
     )
    JOIN cluster_record cont
      ON cont.data->>'kind'       = 'Container'
     AND cont.data->>'cluster_id' = svc.data->>'cluster_id'
     AND cont.data->>'namespace'  = svc.data->>'namespace'
     AND (cont.data->'pod_labels') @> (svc.data->'selector')
     AND COALESCE(cont.data->>'digest', '') <> ''
    WHERE ing.data->>'kind' IN ('Ingress', 'HTTPRoute')
),

-- ---------- chain: cluster has any internet exposure at all ----------
-- For cluster rows: "does this cluster expose anything?" (cheap, no
-- per-digest correlation needed).
exposed_clusters AS (
    SELECT DISTINCT cr.data->>'cluster_id' AS cluster_id
    FROM cluster_record cr
    WHERE cr.data->>'kind' IN ('Ingress','HTTPRoute','GRPCRoute','IngressRoute','IngressRouteTCP')
),

-- ---------- chain: cluster → digests running ----------
cluster_digests AS (
    SELECT DISTINCT
        cr.data->>'cluster_id' AS cluster_id,
        cr.data->>'digest'     AS digest
    FROM cluster_record cr
    WHERE cr.data->>'kind' = 'Container'
      AND COALESCE(cr.data->>'digest', '') <> ''
),

-- ---------- per-vuln, KEV / EPSS bulk lookups ----------
-- Surface the canonical_id from vuln_metadata so KEV/EPSS hit even
-- when the scanner stored a non-CVE alias.
repo_vuln_canonical AS (
    SELECT
        v.repo_id,
        COALESCE(vm.canonical_id, v.vuln_id) AS canonical_id,
        v.severity,
        v.fixed_version,
        v.scanned_at
    FROM view_unified_repositories_vulnerabilities v
    LEFT JOIN vuln_metadata vm ON vm.vuln_id = v.vuln_id
),
image_vuln_canonical AS (
    SELECT
        v.image_id,
        COALESCE(vm.canonical_id, v.vuln_id) AS canonical_id,
        v.severity,
        v.fixed_version,
        v.scanned_at
    FROM view_unified_image_vulnerabilities v
    LEFT JOIN vuln_metadata vm ON vm.vuln_id = v.vuln_id
),

-- ---------- repo-side aggregation ----------
-- One row per repo with all its threat + trust signals collapsed.
-- Counts are over distinct canonical_id within (repo, severity) to
-- avoid double-counting the same advisory reported by both grype and
-- osv on different package paths.
repo_signals AS (
    SELECT
        'repo'::text                                    AS asset_type,
        r.id::text                                      AS asset_id,
        COALESCE(r.org || '/' || r.slug, r.id::text)    AS asset_slug,
        ''::text                                        AS asset_cluster_id,
        -- Threat
        COALESCE(rv.critical_count, 0)::bigint          AS critical_count,
        COALESCE(rv.high_count, 0)::bigint              AS high_count,
        COALESCE(rv.kev_count, 0)::bigint               AS kev_count,
        COALESCE(rv.epss_max, 0)::real                  AS epss_max,
        COALESCE(rv.has_fix_for_critical, false)        AS has_fix_for_critical,
        COALESCE(rs.active_secret_count, 0)::bigint     AS active_secret_count,
        false                                           AS internet_exposed,
        -- Trust
        COALESCE(c.signed_pct, 0)::real                 AS signed_commits_pct,
        false                                           AS image_signed,
        EXTRACT(DAY FROM NOW() - COALESCE(rv.last_scan_at, NOW() - INTERVAL '999 days'))::int
                                                        AS scan_age_days,
        rv.last_scan_at                                 AS last_scan_at,
        EXISTS (SELECT 1 FROM sbom_bindings sb
                JOIN repo_commits rc ON rc.id = sb.asset_ref_id
                WHERE sb.asset_type = 'REPO_COMMIT' AND rc.repo_id = r.id) AS has_sbom,
        -- Dep-health rollup (Phase 3): worst score across the repo's
        -- direct deps, plus counts of archived/deprecated direct deps.
        -- Default 100 when the repo has no manifest_dependencies rows
        -- (means: nothing measured = no penalty).
        COALESCE(dh.worst_score, 100)::real             AS worst_dep_health_score,
        COALESCE(dh.archived_direct, 0)::bigint         AS archived_dep_count,
        COALESCE(dh.deprecated_direct, 0)::bigint       AS deprecated_dep_count
    FROM repos r
    -- Vulns rolled up per repo, deduped on canonical_id within (repo, severity).
    LEFT JOIN LATERAL (
        SELECT
            COUNT(DISTINCT canonical_id) FILTER (WHERE severity = 'CRITICAL')::bigint AS critical_count,
            COUNT(DISTINCT canonical_id) FILTER (WHERE severity = 'HIGH')::bigint     AS high_count,
            COUNT(DISTINCT canonical_id) FILTER (
                WHERE EXISTS (SELECT 1 FROM cisa_kev_entries k WHERE k.cve_id = canonical_id)
            )::bigint AS kev_count,
            (SELECT MAX(score)::real FROM epss_entries e
              WHERE e.cve_id IN (SELECT DISTINCT canonical_id FROM repo_vuln_canonical WHERE repo_id = r.id::text))
                                                                                       AS epss_max,
            BOOL_OR(severity = 'CRITICAL' AND fixed_version <> '')                     AS has_fix_for_critical,
            MAX(scanned_at)                                                            AS last_scan_at
        FROM repo_vuln_canonical
        WHERE repo_id = r.id::text
    ) rv ON TRUE
    -- Active validated secrets in latest run_secrets for this repo.
    LEFT JOIN LATERAL (
        SELECT COUNT(*)::bigint AS active_secret_count
        FROM (
            SELECT DISTINCT ON (repo_id) findings
            FROM run_secrets
            WHERE repo_id = r.id
            ORDER BY repo_id, created_at DESC
        ) latest,
        jsonb_array_elements(COALESCE(latest.findings, '[]'::jsonb)) AS f
        WHERE EXISTS (
            SELECT 1 FROM secret_probes sp
            WHERE sp.status = 'valid'
              AND sp.secret_hash = encode(digest(f->>'Secret', 'sha256'), 'hex')
        )
    ) rs ON TRUE
    -- Commit-signing posture over the last 90 days.
    LEFT JOIN LATERAL (
        SELECT
            CASE WHEN COUNT(*) = 0 THEN 0
                 ELSE (100.0 * COUNT(*) FILTER (WHERE signed = 'G') / COUNT(*))
            END AS signed_pct
        FROM repo_commits
        WHERE repo_id = r.id
          AND author_date > NOW() - INTERVAL '90 days'
    ) c ON TRUE
    -- Dep-health rollup. Joins manifests for the repo → its
    -- dependencies → dep_health records (ecosystem,name keyed). The
    -- worst_score is min across direct deps; counts are direct only
    -- because transitive issues are usually unfixable from the repo
    -- being scored.
    LEFT JOIN LATERAL (
        SELECT
            MIN(d.health_score)::real                                                    AS worst_score,
            COUNT(*) FILTER (WHERE d.is_archived AND md.direct)::bigint                  AS archived_direct,
            COUNT(*) FILTER (WHERE d.is_deprecated AND md.direct)::bigint                AS deprecated_direct
        FROM manifests m
        JOIN manifest_dependencies md ON md.manifest_id = m.id
        JOIN dep_health d
          ON d.ecosystem = md.ecosystem
         AND d.package_name = md.name
        WHERE m.repo_id = r.id
    ) dh ON TRUE
),

-- ---------- image-side aggregation ----------
image_signals AS (
    SELECT
        'image'::text                                   AS asset_type,
        d.id::text                                      AS asset_id,
        COALESCE(NULLIF(d.registry, '') || '/' || d.repository,
                 d.repository, d.id::text)              AS asset_slug,
        ''::text                                        AS asset_cluster_id,
        -- Threat
        COALESCE(iv.critical_count, 0)::bigint          AS critical_count,
        COALESCE(iv.high_count, 0)::bigint              AS high_count,
        COALESCE(iv.kev_count, 0)::bigint               AS kev_count,
        COALESCE(iv.epss_max, 0)::real                  AS epss_max,
        COALESCE(iv.has_fix_for_critical, false)        AS has_fix_for_critical,
        0::bigint                                       AS active_secret_count,
        EXISTS (SELECT 1 FROM exposed_digests ed WHERE ed.digest = d.digest)
                                                        AS internet_exposed,
        -- Trust
        0::real                                         AS signed_commits_pct,
        d.verified_source                               AS image_signed,
        EXTRACT(DAY FROM NOW() - COALESCE(iv.last_scan_at, NOW() - INTERVAL '999 days'))::int
                                                        AS scan_age_days,
        iv.last_scan_at                                 AS last_scan_at,
        EXISTS (SELECT 1 FROM sbom_bindings sb
                WHERE sb.asset_type = 'IMAGE_DIGEST' AND sb.asset_ref_id = d.id) AS has_sbom,
        -- Dep-health doesn't apply at the image level — it's
        -- repo-side (via SBOMs ↔ manifests). Defaults reflect "no
        -- penalty observed" so image rows aren't downgraded for
        -- something they shouldn't be measured on.
        100::real                                       AS worst_dep_health_score,
        0::bigint                                       AS archived_dep_count,
        0::bigint                                       AS deprecated_dep_count
    FROM image_digests d
    LEFT JOIN LATERAL (
        SELECT
            COUNT(DISTINCT canonical_id) FILTER (WHERE severity = 'CRITICAL')::bigint AS critical_count,
            COUNT(DISTINCT canonical_id) FILTER (WHERE severity = 'HIGH')::bigint     AS high_count,
            COUNT(DISTINCT canonical_id) FILTER (
                WHERE EXISTS (SELECT 1 FROM cisa_kev_entries k WHERE k.cve_id = canonical_id)
            )::bigint AS kev_count,
            (SELECT MAX(score)::real FROM epss_entries e
              WHERE e.cve_id IN (SELECT DISTINCT canonical_id FROM image_vuln_canonical WHERE image_id = d.id::text))
                                                                                       AS epss_max,
            BOOL_OR(severity = 'CRITICAL' AND fixed_version <> '')                     AS has_fix_for_critical,
            MAX(scanned_at)                                                            AS last_scan_at
        FROM image_vuln_canonical
        WHERE image_id = d.id::text
    ) iv ON TRUE
),

-- ---------- cluster-side aggregation ----------
-- Roll image vulns up to the cluster: each cluster's threat numbers
-- are the worst signals across all images running in any of its
-- containers. Because we own the cluster→digest binding (k8s API), the
-- rollup is honest even before signing wires up Phase 2.
cluster_signals AS (
    SELECT
        'cluster'::text                                 AS asset_type,
        cluster_id                                      AS asset_id,
        cluster_id                                      AS asset_slug,
        cluster_id                                      AS asset_cluster_id,
        SUM(per_image.critical_count)::bigint           AS critical_count,
        SUM(per_image.high_count)::bigint               AS high_count,
        SUM(per_image.kev_count)::bigint                AS kev_count,
        MAX(per_image.epss_max)::real                   AS epss_max,
        BOOL_OR(per_image.has_fix_for_critical)         AS has_fix_for_critical,
        0::bigint                                       AS active_secret_count,
        EXISTS (SELECT 1 FROM exposed_clusters ec WHERE ec.cluster_id = c.cluster_id)
                                                        AS internet_exposed,
        0::real                                         AS signed_commits_pct,
        false                                           AS image_signed,
        EXTRACT(DAY FROM NOW() - MAX(per_image.last_scan_at))::int
                                                        AS scan_age_days,
        MAX(per_image.last_scan_at)                     AS last_scan_at,
        true                                            AS has_sbom,
        -- Cluster rows don't carry dep-health themselves; that
        -- signal lives on repos. Defaults match image_signals so
        -- the UNION ALL types align.
        100::real                                       AS worst_dep_health_score,
        0::bigint                                       AS archived_dep_count,
        0::bigint                                       AS deprecated_dep_count
    FROM (SELECT DISTINCT cluster_id FROM cluster_digests) c
    LEFT JOIN cluster_digests cd ON cd.cluster_id = c.cluster_id
    LEFT JOIN image_digests d    ON d.digest = cd.digest
    LEFT JOIN LATERAL (
        SELECT
            COUNT(DISTINCT canonical_id) FILTER (WHERE severity = 'CRITICAL')::bigint AS critical_count,
            COUNT(DISTINCT canonical_id) FILTER (WHERE severity = 'HIGH')::bigint     AS high_count,
            COUNT(DISTINCT canonical_id) FILTER (
                WHERE EXISTS (SELECT 1 FROM cisa_kev_entries k WHERE k.cve_id = canonical_id)
            )::bigint AS kev_count,
            (SELECT MAX(score)::real FROM epss_entries e
              WHERE e.cve_id IN (SELECT DISTINCT canonical_id FROM image_vuln_canonical WHERE image_id = d.id::text))
                                                                                       AS epss_max,
            BOOL_OR(severity = 'CRITICAL' AND fixed_version <> '')                     AS has_fix_for_critical,
            MAX(scanned_at)                                                            AS last_scan_at
        FROM image_vuln_canonical
        WHERE image_id = d.id::text
    ) per_image ON TRUE
    GROUP BY c.cluster_id
)

SELECT * FROM repo_signals
UNION ALL SELECT * FROM image_signals
UNION ALL SELECT * FROM cluster_signals
WITH NO DATA;

-- Unique key for REFRESH ... CONCURRENTLY.
CREATE UNIQUE INDEX idx_asset_risk_unique
    ON asset_risk (asset_type, asset_id);

-- Hot predicates for the triage handler's tier filters.
CREATE INDEX idx_asset_risk_kev
    ON asset_risk (kev_count) WHERE kev_count > 0;
CREATE INDEX idx_asset_risk_secrets
    ON asset_risk (active_secret_count) WHERE active_secret_count > 0;
CREATE INDEX idx_asset_risk_exposed
    ON asset_risk (internet_exposed) WHERE internet_exposed;
CREATE INDEX idx_asset_risk_critical
    ON asset_risk (critical_count) WHERE critical_count > 0;
