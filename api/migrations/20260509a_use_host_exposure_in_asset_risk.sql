-- Drop the two `exposed_digests` UNIONed CTEs from asset_risk and let
-- the WHERE/EXISTS clauses resolve `exposed_digests` to the new
-- materialized view created in 20260509_create_host_exposure_views.sql.
--
-- This consolidates the Ingress → Service → Container chain
-- traversal in one place: the hosts list and asset_risk both read
-- the same projection, so high-volume Container ingest only invalidates
-- exposed_digests once per coalesced refresh window instead of forcing
-- the much larger asset_risk body to recompute the chain every time.
--
-- The rest of the asset_risk body is unchanged from
-- 20260506_create_asset_risk_view.sql.
--
-- Hash-bump note: 20260509_create_host_exposure_views.sql now uses
-- DROP MATERIALIZED VIEW ... CASCADE because asset_risk depends on
-- exposed_digests. The CASCADE drops asset_risk too — this migration
-- must re-run in the same EnsureViews pass to recreate it. The
-- comment edit here exists solely to bump this file's sha256 so the
-- hash check picks it up; the SQL body below is unchanged.

DROP MATERIALIZED VIEW IF EXISTS asset_risk;

CREATE MATERIALIZED VIEW asset_risk AS
WITH
-- ---------- chain: cluster → digests currently running ----------
-- See 20260506_create_asset_risk_view.sql for the rationale on why
-- this trusts msg<>'DELETE' rather than gating on received_at.
cluster_digests AS (
    SELECT DISTINCT
        cr.data->>'cluster_id' AS cluster_id,
        cr.data->>'digest'     AS digest
    FROM cluster_record cr
    WHERE cr.data->>'kind' = 'Container'
      AND COALESCE(cr.data->>'digest', '') <> ''
      AND COALESCE(cr.data->>'msg', '')   <> 'DELETE'
),

-- ---------- per-vuln, KEV / EPSS bulk lookups ----------
repo_vuln_canonical AS (
    SELECT
        v.repo_id,
        COALESCE(vm.canonical_id, v.vuln_id) AS canonical_id,
        v.severity,
        v.fixed_version,
        v.scanned_at
    FROM view_unified_repositories_vulnerabilities v
    LEFT JOIN vuln_metadata vm ON vm.vuln_id = v.vuln_id
    WHERE NOT EXISTS (
        SELECT 1
        FROM component_vex vex
        LEFT JOIN vuln_metadata vmx ON vmx.vuln_id = vex.vuln_id
        JOIN sbom_component_view sc ON sc.purl = vex.p_url
        JOIN sbom_bindings sb       ON sb.sbom_id      = sc.sbom_id
                                   AND sb.asset_type  = 'REPO_COMMIT'
        JOIN repo_commits rc        ON rc.id           = sb.asset_ref_id
        WHERE vex.status IN ('not_affected', 'fixed')
          AND COALESCE(vmx.canonical_id, vex.vuln_id)
              = COALESCE(vm.canonical_id, v.vuln_id)
          AND rc.repo_id::text = v.repo_id
    )
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
    WHERE NOT EXISTS (
        SELECT 1
        FROM component_vex vex
        LEFT JOIN vuln_metadata vmx ON vmx.vuln_id = vex.vuln_id
        JOIN sbom_component_view sc ON sc.purl = vex.p_url
        JOIN sbom_bindings sb       ON sb.sbom_id      = sc.sbom_id
                                   AND sb.asset_type  = 'IMAGE_DIGEST'
        WHERE vex.status IN ('not_affected', 'fixed')
          AND COALESCE(vmx.canonical_id, vex.vuln_id)
              = COALESCE(vm.canonical_id, v.vuln_id)
          AND sb.asset_ref_id::text = v.image_id
    )
),

-- ---------- chain: cluster has internet-exposed *vulnerable* workload ----------
-- `exposed_digests` here resolves to the materialized view created in
-- 20260509_create_host_exposure_views.sql; only `digest` and
-- `cluster_id` are read so the additional MV columns are inert.
exposed_clusters AS (
    SELECT DISTINCT ed.cluster_id
    FROM exposed_digests ed
    JOIN image_digests id ON id.digest = ed.digest
    WHERE EXISTS (
        SELECT 1 FROM image_vuln_canonical ivc
        WHERE ivc.image_id = id.id::text
          AND ivc.severity IN ('CRITICAL', 'HIGH', 'MEDIUM')
    )
),

-- ---------- repo-side aggregation ----------
repo_signals AS (
    SELECT
        'repo'::text                                    AS asset_type,
        r.id::text                                      AS asset_id,
        COALESCE(r.org || '/' || r.slug, r.id::text)    AS asset_slug,
        ''::text                                        AS asset_cluster_id,
        COALESCE(rv.critical_count, 0)::bigint          AS critical_count,
        COALESCE(rv.high_count, 0)::bigint              AS high_count,
        COALESCE(rv.kev_count, 0)::bigint               AS kev_count,
        COALESCE(rv.epss_max, 0)::real                  AS epss_max,
        COALESCE(rv.has_fix_for_critical, false)        AS has_fix_for_critical,
        COALESCE(rs.active_secret_count, 0)::bigint     AS active_secret_count,
        false                                           AS internet_exposed,
        COALESCE(c.signed_pct, 0)::real                 AS signed_commits_pct,
        false                                           AS image_signed,
        EXTRACT(DAY FROM NOW() - COALESCE(sa.last_scan_at, NOW() - INTERVAL '999 days'))::int
                                                        AS scan_age_days,
        sa.last_scan_at                                 AS last_scan_at,
        EXISTS (SELECT 1 FROM sbom_bindings sb
                JOIN repo_commits rc ON rc.id = sb.asset_ref_id
                WHERE sb.asset_type = 'REPO_COMMIT' AND rc.repo_id = r.id) AS has_sbom,
        COALESCE(dh.worst_score, 100)::real             AS worst_dep_health_score,
        COALESCE(dh.archived_direct, 0)::bigint         AS archived_dep_count,
        COALESCE(dh.deprecated_direct, 0)::bigint       AS deprecated_dep_count,
        COALESCE(dh.max_major_behind, 0)::int           AS max_major_behind,
        COALESCE(dh.major_behind_direct, 0)::bigint     AS major_behind_dep_count
    FROM repos r
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
    LEFT JOIN LATERAL (
        SELECT GREATEST(
            (SELECT MAX(sr.scanned_at)
               FROM sbom_scan_results sr
               JOIN sbom_bindings sb  ON sb.sbom_id = sr.sbom_id AND sb.asset_type = 'REPO_COMMIT'
               JOIN repo_commits rc   ON rc.id = sb.asset_ref_id
              WHERE rc.repo_id = r.id),
            (SELECT MAX(rs2.created_at) FROM run_secrets rs2 WHERE rs2.repo_id = r.id)
        ) AS last_scan_at
    ) sa ON TRUE
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
    LEFT JOIN LATERAL (
        SELECT
            CASE WHEN COUNT(*) = 0 THEN 0
                 ELSE (100.0 * COUNT(*) FILTER (WHERE signed = 'G') / COUNT(*))
            END AS signed_pct
        FROM repo_commits
        WHERE repo_id = r.id
          AND author_date > NOW() - INTERVAL '90 days'
    ) c ON TRUE
    LEFT JOIN LATERAL (
        SELECT
            MIN(d.health_score)::real                                                    AS worst_score,
            COUNT(*) FILTER (WHERE d.is_archived AND md.direct)::bigint                  AS archived_direct,
            COUNT(*) FILTER (WHERE d.is_deprecated AND md.direct)::bigint                AS deprecated_direct,
            COALESCE(MAX(d.versions_behind_major) FILTER (WHERE md.direct), 0)::int      AS max_major_behind,
            COUNT(*) FILTER (WHERE d.versions_behind_major > 0 AND md.direct)::bigint    AS major_behind_direct
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
        COALESCE(iv.critical_count, 0)::bigint          AS critical_count,
        COALESCE(iv.high_count, 0)::bigint              AS high_count,
        COALESCE(iv.kev_count, 0)::bigint               AS kev_count,
        COALESCE(iv.epss_max, 0)::real                  AS epss_max,
        COALESCE(iv.has_fix_for_critical, false)        AS has_fix_for_critical,
        0::bigint                                       AS active_secret_count,
        EXISTS (SELECT 1 FROM exposed_digests ed WHERE ed.digest = d.digest)
                                                        AS internet_exposed,
        0::real                                         AS signed_commits_pct,
        d.verified_source                               AS image_signed,
        EXTRACT(DAY FROM NOW() - COALESCE(isa.last_scan_at, NOW() - INTERVAL '999 days'))::int
                                                        AS scan_age_days,
        isa.last_scan_at                                AS last_scan_at,
        EXISTS (SELECT 1 FROM sbom_bindings sb
                WHERE sb.asset_type = 'IMAGE_DIGEST' AND sb.asset_ref_id = d.id) AS has_sbom,
        COALESCE(idh.worst_score, 100)::real            AS worst_dep_health_score,
        COALESCE(idh.archived_direct, 0)::bigint        AS archived_dep_count,
        COALESCE(idh.deprecated_direct, 0)::bigint      AS deprecated_dep_count,
        COALESCE(idh.max_major_behind, 0)::int          AS max_major_behind,
        COALESCE(idh.major_behind_direct, 0)::bigint    AS major_behind_dep_count
    FROM image_digests d
    JOIN (SELECT DISTINCT digest FROM cluster_digests) cd ON cd.digest = d.digest
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
    LEFT JOIN LATERAL (
        SELECT MAX(isr.finished_at) AS last_scan_at
        FROM image_scan_runs isr
        WHERE isr.image_digest_id = d.id
          AND isr.finished_at IS NOT NULL
    ) isa ON TRUE
    LEFT JOIN LATERAL (
        SELECT
            MIN(dh.health_score)::real                                  AS worst_score,
            COUNT(*) FILTER (WHERE dh.is_archived)::bigint              AS archived_direct,
            COUNT(*) FILTER (WHERE dh.is_deprecated)::bigint            AS deprecated_direct,
            COALESCE(MAX(dh.versions_behind_major), 0)::int             AS max_major_behind,
            COUNT(*) FILTER (WHERE dh.versions_behind_major > 0)::bigint AS major_behind_direct
        FROM sbom_component_view sc
        JOIN dep_health dh
          ON dh.ecosystem = CASE sc.kind
                              WHEN 'golang' THEN 'go'
                              WHEN 'gem'    THEN 'rubygems'
                              ELSE sc.kind
                            END
         AND dh.package_name = sc.package_name
        WHERE sc.asset_type = 'IMAGE_DIGEST'
          AND sc.asset_ref_id = d.id
          AND sc.is_root = false
    ) idh ON TRUE
),

-- ---------- cluster-side aggregation ----------
cluster_canonical AS (
    SELECT
        cd.cluster_id,
        ivc.canonical_id,
        MIN(CASE ivc.severity
            WHEN 'CRITICAL' THEN 1
            WHEN 'HIGH'     THEN 2
            WHEN 'MEDIUM'   THEN 3
            WHEN 'LOW'      THEN 4
            ELSE 5
        END)                                AS sev_rank,
        BOOL_OR(ivc.fixed_version <> '')    AS any_fixed,
        MAX(ivc.scanned_at)                 AS last_scan_at
    FROM cluster_digests cd
    JOIN image_digests d         ON d.digest    = cd.digest
    JOIN image_vuln_canonical ivc ON ivc.image_id = d.id::text
    GROUP BY cd.cluster_id, ivc.canonical_id
),

cluster_signals AS (
    SELECT
        'cluster'::text                                                    AS asset_type,
        c.cluster_id                                                       AS asset_id,
        c.cluster_id                                                       AS asset_slug,
        c.cluster_id                                                       AS asset_cluster_id,
        COUNT(*) FILTER (WHERE cc.sev_rank = 1)::bigint                    AS critical_count,
        COUNT(*) FILTER (WHERE cc.sev_rank = 2)::bigint                    AS high_count,
        COUNT(*) FILTER (
            WHERE EXISTS (SELECT 1 FROM cisa_kev_entries k WHERE k.cve_id = cc.canonical_id)
        )::bigint                                                          AS kev_count,
        COALESCE(MAX(e.score), 0)::real                                    AS epss_max,
        COALESCE(BOOL_OR(cc.sev_rank = 1 AND cc.any_fixed), false)         AS has_fix_for_critical,
        0::bigint                                                          AS active_secret_count,
        EXISTS (SELECT 1 FROM exposed_clusters ec WHERE ec.cluster_id = c.cluster_id)
                                                                           AS internet_exposed,
        0::real                                                            AS signed_commits_pct,
        false                                                              AS image_signed,
        EXTRACT(DAY FROM NOW() - COALESCE(MAX(cc.last_scan_at), NOW() - INTERVAL '999 days'))::int
                                                                           AS scan_age_days,
        MAX(cc.last_scan_at)                                               AS last_scan_at,
        true                                                               AS has_sbom,
        COALESCE(cluster_dh.worst_score, 100)::real                        AS worst_dep_health_score,
        COALESCE(cluster_dh.archived_count, 0)::bigint                     AS archived_dep_count,
        COALESCE(cluster_dh.deprecated_count, 0)::bigint                   AS deprecated_dep_count,
        COALESCE(cluster_dh.max_major_behind, 0)::int                      AS max_major_behind,
        COALESCE(cluster_dh.major_behind_count, 0)::bigint                 AS major_behind_dep_count
    FROM (SELECT DISTINCT cluster_id FROM cluster_digests) c
    LEFT JOIN cluster_canonical cc ON cc.cluster_id = c.cluster_id
    LEFT JOIN epss_entries e       ON e.cve_id     = cc.canonical_id
    LEFT JOIN LATERAL (
        SELECT
            MIN(dh.health_score)::real                                       AS worst_score,
            COUNT(*) FILTER (WHERE dh.is_archived)::bigint                   AS archived_count,
            COUNT(*) FILTER (WHERE dh.is_deprecated)::bigint                 AS deprecated_count,
            COALESCE(MAX(dh.versions_behind_major), 0)::int                  AS max_major_behind,
            COUNT(*) FILTER (WHERE dh.versions_behind_major > 0)::bigint     AS major_behind_count
        FROM cluster_digests cd
        JOIN image_digests d ON d.digest = cd.digest
        JOIN sbom_component_view sc
          ON sc.asset_type   = 'IMAGE_DIGEST'
         AND sc.asset_ref_id = d.id
         AND sc.is_root      = false
        JOIN dep_health dh
          ON dh.ecosystem = CASE sc.kind
                              WHEN 'golang' THEN 'go'
                              WHEN 'gem'    THEN 'rubygems'
                              ELSE sc.kind
                            END
         AND dh.package_name = sc.package_name
        WHERE cd.cluster_id = c.cluster_id
    ) cluster_dh ON TRUE
    GROUP BY c.cluster_id, cluster_dh.worst_score, cluster_dh.archived_count,
             cluster_dh.deprecated_count, cluster_dh.max_major_behind,
             cluster_dh.major_behind_count
)

SELECT * FROM repo_signals
UNION ALL SELECT * FROM image_signals
UNION ALL SELECT * FROM cluster_signals
WITH NO DATA;

-- Recreate indexes that DROP MATERIALIZED VIEW removed.
CREATE UNIQUE INDEX idx_asset_risk_unique
    ON asset_risk (asset_type, asset_id);

CREATE INDEX idx_asset_risk_kev
    ON asset_risk (kev_count) WHERE kev_count > 0;
CREATE INDEX idx_asset_risk_secrets
    ON asset_risk (active_secret_count) WHERE active_secret_count > 0;
CREATE INDEX idx_asset_risk_exposed
    ON asset_risk (internet_exposed) WHERE internet_exposed;
CREATE INDEX idx_asset_risk_critical
    ON asset_risk (critical_count) WHERE critical_count > 0;
