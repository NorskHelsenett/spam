-- Replace asset_risk's per-row LATERAL joins with pre-aggregated CTEs.
--
-- The previous body (20260509a) computed every per-repo, per-image, and
-- per-cluster signal as a separate LATERAL subquery: for each row in
-- repos / image_digests / cluster_digests it re-ran a GROUP BY over
-- run_secrets / sbom_component_view / dep_health / repo_commits /
-- manifest_dependencies. At fleet scale a single REFRESH ran past the
-- 30-min budget — repo_signals.rs alone computed sha256 over every
-- finding × every repo, which is O(repos × findings_per_repo) hash
-- compute even though the secret_probes lookup is keyed by hash and
-- only depends on the *finding*, not which repo carries it.
--
-- This migration restructures the body so each table is scanned and
-- aggregated exactly once, then attached to the parent rows via
-- index-only LEFT JOINs. The output schema is unchanged — every column
-- in asset_risk has the same semantics as before, the read handler
-- doesn't move.
--
-- Hot-spot rewrites:
--
--   repo_active_secrets   one pass over the latest run_secrets per
--                         repo, expand findings, hash, JOIN to
--                         secret_probes — instead of the same work
--                         per repo. SHA256 cost drops from
--                         O(repos × findings) to O(findings).
--
--   repo_dep_health       single GROUP BY over manifests ⋈
--                         manifest_dependencies ⋈ dep_health.
--                         Replaces the per-repo LATERAL.
--
--   image_dep_health      single GROUP BY over sbom_component_view ⋈
--                         dep_health for asset_type='IMAGE_DIGEST'.
--                         Replaces the per-image LATERAL.
--
--   cluster_dep_health    single GROUP BY over cluster_digests ⋈
--                         image_digests ⋈ sbom_component_view ⋈
--                         dep_health. Replaces the per-cluster
--                         LATERAL — biggest single win because the
--                         join chain is widest.
--
--   repo_vuln_agg /       GROUP BY canonical → (severity, kev,
--   image_vuln_agg        fix_available, last_scan, epss_max). Inlines
--                         the cisa_kev_entries EXISTS via LEFT JOIN
--                         and the epss_entries MAX via a side CTE so
--                         the planner sees a flat aggregation.
--
--   repo_last_scan /      Two-source MAX(scanned_at) collapses into a
--   image_last_scan       UNION ALL feeding a single GROUP BY rather
--                         than nested correlated subqueries.
--
--   repo_signed_pct       GROUP BY over repo_commits filtered to the
--                         90-day window once. The old version filtered
--                         once per repo.
--
-- Unaffected (kept as-is): cluster_canonical (already a GROUP BY),
-- has_sbom EXISTS (cheap when the sbom_bindings index is in place),
-- internet_exposed EXISTS (exposed_digests is small), and the VEX
-- NOT EXISTS inside repo_vuln_canonical / image_vuln_canonical (the
-- canonical CTEs are GROUP BY-driven, not per-row).

DROP MATERIALIZED VIEW IF EXISTS asset_risk;

CREATE MATERIALIZED VIEW asset_risk AS
WITH
-- ---------- chain: cluster → digests currently running ----------
cluster_digests AS (
    SELECT DISTINCT
        cr.data->>'cluster_id' AS cluster_id,
        cr.data->>'digest'     AS digest
    FROM cluster_record cr
    WHERE cr.data->>'kind' = 'Container'
      AND COALESCE(cr.data->>'digest', '') <> ''
      AND COALESCE(cr.data->>'msg', '')   <> 'DELETE'
),

-- ---------- per-vuln canonical projections (with VEX exclusion) ----------
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
        JOIN sbom_bindings sb       ON sb.sbom_id     = sc.sbom_id
                                   AND sb.asset_type = 'REPO_COMMIT'
        JOIN repo_commits rc        ON rc.id          = sb.asset_ref_id
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
        JOIN sbom_bindings sb       ON sb.sbom_id     = sc.sbom_id
                                   AND sb.asset_type = 'IMAGE_DIGEST'
        WHERE vex.status IN ('not_affected', 'fixed')
          AND COALESCE(vmx.canonical_id, vex.vuln_id)
              = COALESCE(vm.canonical_id, v.vuln_id)
          AND sb.asset_ref_id::text = v.image_id
    )
),

-- ---------- chain: cluster has internet-exposed *vulnerable* workload ----------
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

-- ---------- repo pre-aggregations ----------
repo_vuln_agg AS (
    SELECT
        rvc.repo_id,
        COUNT(DISTINCT rvc.canonical_id) FILTER (WHERE rvc.severity = 'CRITICAL')::bigint AS critical_count,
        COUNT(DISTINCT rvc.canonical_id) FILTER (WHERE rvc.severity = 'HIGH')::bigint     AS high_count,
        COUNT(DISTINCT rvc.canonical_id) FILTER (WHERE k.cve_id IS NOT NULL)::bigint      AS kev_count,
        BOOL_OR(rvc.severity = 'CRITICAL' AND rvc.fixed_version <> '')                    AS has_fix_for_critical,
        MAX(rvc.scanned_at)                                                               AS last_scan_at
    FROM repo_vuln_canonical rvc
    LEFT JOIN cisa_kev_entries k ON k.cve_id = rvc.canonical_id
    GROUP BY rvc.repo_id
),
repo_epss_max AS (
    SELECT
        rvc.repo_id,
        MAX(e.score)::real AS epss_max
    FROM repo_vuln_canonical rvc
    JOIN epss_entries e ON e.cve_id = rvc.canonical_id
    GROUP BY rvc.repo_id
),
repo_last_scan AS (
    -- Combine SBOM scan timestamps and run_secrets timestamps in one
    -- aggregation. UNION ALL is fine — duplicates between the two
    -- sources don't change the per-repo MAX.
    SELECT u.repo_id, MAX(u.t) AS last_scan_at
    FROM (
        SELECT rc.repo_id, MAX(sr.scanned_at) AS t
        FROM sbom_scan_results sr
        JOIN sbom_bindings sb ON sb.sbom_id = sr.sbom_id AND sb.asset_type = 'REPO_COMMIT'
        JOIN repo_commits rc  ON rc.id      = sb.asset_ref_id
        GROUP BY rc.repo_id
        UNION ALL
        SELECT rs.repo_id, MAX(rs.created_at) AS t
        FROM run_secrets rs
        WHERE rs.repo_id IS NOT NULL
        GROUP BY rs.repo_id
    ) u
    GROUP BY u.repo_id
),
repo_active_secrets AS (
    -- One global pass: take the latest run_secrets row per repo,
    -- expand its findings, sha256 each one, join to secret_probes,
    -- and aggregate. Replaces the per-repo LATERAL that re-hashed
    -- every finding O(repos) times.
    SELECT lr.repo_id, COUNT(*)::bigint AS active_secret_count
    FROM (
        SELECT DISTINCT ON (repo_id) repo_id, findings
        FROM run_secrets
        WHERE repo_id IS NOT NULL
        ORDER BY repo_id, created_at DESC
    ) lr
    CROSS JOIN LATERAL jsonb_array_elements(COALESCE(lr.findings, '[]'::jsonb)) AS f
    JOIN secret_probes sp
      ON sp.status      = 'valid'
     AND sp.secret_hash = encode(digest(f->>'Secret', 'sha256'), 'hex')
    GROUP BY lr.repo_id
),
repo_signed_pct AS (
    -- GROUP BY repo_id once over the 90-day window; the old version
    -- filtered the same set per repo through a LATERAL.
    SELECT
        rc.repo_id,
        CASE WHEN COUNT(*) = 0 THEN 0
             ELSE (100.0 * COUNT(*) FILTER (WHERE rc.signed = 'G') / COUNT(*))
        END::real AS signed_pct
    FROM repo_commits rc
    WHERE rc.author_date > NOW() - INTERVAL '90 days'
    GROUP BY rc.repo_id
),
repo_dep_health AS (
    SELECT
        m.repo_id,
        MIN(d.health_score)::real                                                    AS worst_score,
        COUNT(*) FILTER (WHERE d.is_archived AND md.direct)::bigint                  AS archived_direct,
        COUNT(*) FILTER (WHERE d.is_deprecated AND md.direct)::bigint                AS deprecated_direct,
        COALESCE(MAX(d.versions_behind_major) FILTER (WHERE md.direct), 0)::int      AS max_major_behind,
        COUNT(*) FILTER (WHERE d.versions_behind_major > 0 AND md.direct)::bigint    AS major_behind_direct
    FROM manifests m
    JOIN manifest_dependencies md ON md.manifest_id = m.id
    JOIN dep_health d
      ON d.ecosystem    = md.ecosystem
     AND d.package_name = md.name
    GROUP BY m.repo_id
),
repo_has_sbom AS (
    SELECT DISTINCT rc.repo_id
    FROM sbom_bindings sb
    JOIN repo_commits rc ON rc.id = sb.asset_ref_id
    WHERE sb.asset_type = 'REPO_COMMIT'
),

-- ---------- repo signals (flat LEFT JOINs over the pre-aggregations) ----------
repo_signals AS (
    SELECT
        'repo'::text                                    AS asset_type,
        r.id::text                                      AS asset_id,
        COALESCE(r.org || '/' || r.slug, r.id::text)    AS asset_slug,
        ''::text                                        AS asset_cluster_id,
        COALESCE(rva.critical_count, 0)::bigint         AS critical_count,
        COALESCE(rva.high_count, 0)::bigint             AS high_count,
        COALESCE(rva.kev_count, 0)::bigint              AS kev_count,
        COALESCE(rem.epss_max, 0)::real                 AS epss_max,
        COALESCE(rva.has_fix_for_critical, false)       AS has_fix_for_critical,
        COALESCE(ras.active_secret_count, 0)::bigint    AS active_secret_count,
        false                                           AS internet_exposed,
        COALESCE(rsp.signed_pct, 0)::real               AS signed_commits_pct,
        false                                           AS image_signed,
        EXTRACT(DAY FROM NOW() - COALESCE(rls.last_scan_at, NOW() - INTERVAL '999 days'))::int
                                                        AS scan_age_days,
        rls.last_scan_at                                AS last_scan_at,
        (rhs.repo_id IS NOT NULL)                       AS has_sbom,
        COALESCE(rdh.worst_score, 100)::real            AS worst_dep_health_score,
        COALESCE(rdh.archived_direct, 0)::bigint        AS archived_dep_count,
        COALESCE(rdh.deprecated_direct, 0)::bigint      AS deprecated_dep_count,
        COALESCE(rdh.max_major_behind, 0)::int          AS max_major_behind,
        COALESCE(rdh.major_behind_direct, 0)::bigint    AS major_behind_dep_count
    FROM repos r
    LEFT JOIN repo_vuln_agg     rva ON rva.repo_id = r.id::text
    LEFT JOIN repo_epss_max     rem ON rem.repo_id = r.id::text
    LEFT JOIN repo_last_scan    rls ON rls.repo_id = r.id
    LEFT JOIN repo_active_secrets ras ON ras.repo_id = r.id
    LEFT JOIN repo_signed_pct   rsp ON rsp.repo_id = r.id
    LEFT JOIN repo_dep_health   rdh ON rdh.repo_id = r.id
    LEFT JOIN repo_has_sbom     rhs ON rhs.repo_id = r.id
),

-- ---------- image pre-aggregations ----------
image_vuln_agg AS (
    SELECT
        ivc.image_id,
        COUNT(DISTINCT ivc.canonical_id) FILTER (WHERE ivc.severity = 'CRITICAL')::bigint AS critical_count,
        COUNT(DISTINCT ivc.canonical_id) FILTER (WHERE ivc.severity = 'HIGH')::bigint     AS high_count,
        COUNT(DISTINCT ivc.canonical_id) FILTER (WHERE k.cve_id IS NOT NULL)::bigint      AS kev_count,
        BOOL_OR(ivc.severity = 'CRITICAL' AND ivc.fixed_version <> '')                    AS has_fix_for_critical,
        MAX(ivc.scanned_at)                                                               AS last_scan_at
    FROM image_vuln_canonical ivc
    LEFT JOIN cisa_kev_entries k ON k.cve_id = ivc.canonical_id
    GROUP BY ivc.image_id
),
image_epss_max AS (
    SELECT
        ivc.image_id,
        MAX(e.score)::real AS epss_max
    FROM image_vuln_canonical ivc
    JOIN epss_entries e ON e.cve_id = ivc.canonical_id
    GROUP BY ivc.image_id
),
image_last_scan AS (
    SELECT image_digest_id AS image_id, MAX(finished_at) AS last_scan_at
    FROM image_scan_runs
    WHERE finished_at IS NOT NULL
    GROUP BY image_digest_id
),
image_dep_health AS (
    SELECT
        sc.asset_ref_id                                              AS image_id,
        MIN(dh.health_score)::real                                   AS worst_score,
        COUNT(*) FILTER (WHERE dh.is_archived)::bigint               AS archived_direct,
        COUNT(*) FILTER (WHERE dh.is_deprecated)::bigint             AS deprecated_direct,
        COALESCE(MAX(dh.versions_behind_major), 0)::int              AS max_major_behind,
        COUNT(*) FILTER (WHERE dh.versions_behind_major > 0)::bigint AS major_behind_direct
    FROM sbom_component_view sc
    JOIN dep_health dh
      ON dh.ecosystem    = CASE sc.kind
                              WHEN 'golang' THEN 'go'
                              WHEN 'gem'    THEN 'rubygems'
                              ELSE sc.kind
                            END
     AND dh.package_name = sc.package_name
    WHERE sc.asset_type = 'IMAGE_DIGEST'
      AND sc.is_root    = false
    GROUP BY sc.asset_ref_id
),
image_has_sbom AS (
    SELECT DISTINCT asset_ref_id AS image_id
    FROM sbom_bindings
    WHERE asset_type = 'IMAGE_DIGEST'
),
image_internet_exposed AS (
    SELECT DISTINCT digest FROM exposed_digests
),

-- ---------- image signals ----------
image_signals AS (
    SELECT
        'image'::text                                   AS asset_type,
        d.id::text                                      AS asset_id,
        COALESCE(NULLIF(d.registry, '') || '/' || d.repository,
                 d.repository, d.id::text)              AS asset_slug,
        ''::text                                        AS asset_cluster_id,
        COALESCE(iva.critical_count, 0)::bigint         AS critical_count,
        COALESCE(iva.high_count, 0)::bigint             AS high_count,
        COALESCE(iva.kev_count, 0)::bigint              AS kev_count,
        COALESCE(iem.epss_max, 0)::real                 AS epss_max,
        COALESCE(iva.has_fix_for_critical, false)       AS has_fix_for_critical,
        0::bigint                                       AS active_secret_count,
        (iie.digest IS NOT NULL)                        AS internet_exposed,
        0::real                                         AS signed_commits_pct,
        d.verified_source                               AS image_signed,
        EXTRACT(DAY FROM NOW() - COALESCE(ils.last_scan_at, NOW() - INTERVAL '999 days'))::int
                                                        AS scan_age_days,
        ils.last_scan_at                                AS last_scan_at,
        (ihs.image_id IS NOT NULL)                      AS has_sbom,
        COALESCE(idh.worst_score, 100)::real            AS worst_dep_health_score,
        COALESCE(idh.archived_direct, 0)::bigint        AS archived_dep_count,
        COALESCE(idh.deprecated_direct, 0)::bigint      AS deprecated_dep_count,
        COALESCE(idh.max_major_behind, 0)::int          AS max_major_behind,
        COALESCE(idh.major_behind_direct, 0)::bigint    AS major_behind_dep_count
    FROM image_digests d
    JOIN (SELECT DISTINCT digest FROM cluster_digests) cd ON cd.digest = d.digest
    LEFT JOIN image_vuln_agg     iva ON iva.image_id = d.id::text
    LEFT JOIN image_epss_max     iem ON iem.image_id = d.id::text
    LEFT JOIN image_last_scan    ils ON ils.image_id = d.id
    LEFT JOIN image_dep_health   idh ON idh.image_id = d.id
    LEFT JOIN image_has_sbom     ihs ON ihs.image_id = d.id
    LEFT JOIN image_internet_exposed iie ON iie.digest = d.digest
),

-- ---------- cluster pre-aggregations ----------
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
cluster_dep_health AS (
    SELECT
        cd.cluster_id,
        MIN(dh.health_score)::real                                   AS worst_score,
        COUNT(*) FILTER (WHERE dh.is_archived)::bigint               AS archived_count,
        COUNT(*) FILTER (WHERE dh.is_deprecated)::bigint             AS deprecated_count,
        COALESCE(MAX(dh.versions_behind_major), 0)::int              AS max_major_behind,
        COUNT(*) FILTER (WHERE dh.versions_behind_major > 0)::bigint AS major_behind_count
    FROM cluster_digests cd
    JOIN image_digests d ON d.digest = cd.digest
    JOIN sbom_component_view sc
      ON sc.asset_type   = 'IMAGE_DIGEST'
     AND sc.asset_ref_id = d.id
     AND sc.is_root      = false
    JOIN dep_health dh
      ON dh.ecosystem    = CASE sc.kind
                              WHEN 'golang' THEN 'go'
                              WHEN 'gem'    THEN 'rubygems'
                              ELSE sc.kind
                            END
     AND dh.package_name = sc.package_name
    GROUP BY cd.cluster_id
),

-- ---------- cluster signals ----------
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
        (ec.cluster_id IS NOT NULL)                                        AS internet_exposed,
        0::real                                                            AS signed_commits_pct,
        false                                                              AS image_signed,
        EXTRACT(DAY FROM NOW() - COALESCE(MAX(cc.last_scan_at), NOW() - INTERVAL '999 days'))::int
                                                                           AS scan_age_days,
        MAX(cc.last_scan_at)                                               AS last_scan_at,
        true                                                               AS has_sbom,
        COALESCE(cdh.worst_score, 100)::real                               AS worst_dep_health_score,
        COALESCE(cdh.archived_count, 0)::bigint                            AS archived_dep_count,
        COALESCE(cdh.deprecated_count, 0)::bigint                          AS deprecated_dep_count,
        COALESCE(cdh.max_major_behind, 0)::int                             AS max_major_behind,
        COALESCE(cdh.major_behind_count, 0)::bigint                        AS major_behind_dep_count
    FROM (SELECT DISTINCT cluster_id FROM cluster_digests) c
    LEFT JOIN cluster_canonical  cc ON cc.cluster_id = c.cluster_id
    LEFT JOIN epss_entries        e ON e.cve_id      = cc.canonical_id
    LEFT JOIN cluster_dep_health cdh ON cdh.cluster_id = c.cluster_id
    LEFT JOIN exposed_clusters   ec ON ec.cluster_id   = c.cluster_id
    GROUP BY c.cluster_id, cdh.worst_score, cdh.archived_count,
             cdh.deprecated_count, cdh.max_major_behind,
             cdh.major_behind_count, ec.cluster_id
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
