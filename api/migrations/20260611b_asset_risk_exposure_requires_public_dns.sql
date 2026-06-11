-- internet_exposed must mean "reachable from the internet", not
-- "published through an Ingress".
--
-- asset_risk's exposure signals (internet_exposed, exposed_kev_count,
-- exposed_critical_count, exposed_epss_max, exposed_cluster_count)
-- were built on bare exposed_digests membership: every digest behind
-- ANY Ingress/Gateway host counted as internet-exposed, even when the
-- host only resolves in the internal zone (e.g. a split-DNS name with
-- no public record). The hostresolve worker has classified every
-- ingress host as internal/external since 20260527 — and gained a
-- public-DNS DoH vantage in 20260611 — but the signals never consulted
-- it. Result: internal-only services drove fix_now tiers and the LLM
-- advisory/chat payloads confidently claimed public reachability.
--
-- publicly_exposed_digests is the gated projection: exposed_digests
-- restricted to hosts whose DNS verdict does not rule out public
-- reachability. Counted as exposed:
--   external        — public answer, public address
--   pending / no row — worker hasn't resolved it yet; stay conservative
--                      (over-report, never under-report) until it does
-- Not counted:
--   internal        — resolves only to private space; public DNS has
--                      no host-specific record
--   unresolvable    — neither vantage resolves it and no LB-IP
--                      fallback: unreachable by that name
--
-- Go-side exposure booleans (triage image detail, chat payload's
-- runs_in_clusters) read this view too, so the tier engine, the API,
-- and the LLM grounding all share one definition of "exposed".
-- Host *listings* (exposed-hosts tables, the chat payload's
-- exposed_hosts) deliberately stay on exposed_digests — they enumerate
-- ingress-published names and carry per-host classification.
--
-- Hash-bump note (inherited from 20260610): 20260509 drops
-- exposed_digests with CASCADE, which transitively drops both this
-- view and asset_risk. Whenever the host_exposure migration's SHA
-- changes, this file's SHA must also change — the EnsureViews
-- matview-existence recheck sees asset_risk missing and reapplies this
-- whole file, recreating the view alongside it. This file supersedes
-- 20260610 as the last asset_risk creator.

CREATE OR REPLACE VIEW publicly_exposed_digests AS
SELECT ed.cluster_id,
       ed.namespace,
       ed.host,
       ed.exposure_kind,
       ed.exposure_name,
       ed.digest
FROM exposed_digests ed
LEFT JOIN host_resolution hr ON hr.host = ed.host
WHERE COALESCE(hr.classification, 'pending') NOT IN ('internal', 'unresolvable');

-- Bootstrap deadlock avoidance — same dance as 20260610: cancel any
-- in-flight asset_risk REFRESH so DROP can take its lock, and bound
-- the wait so a stuck peer fails this bootstrap instead of hanging it.
DO $$
BEGIN
    PERFORM pg_cancel_backend(pid)
    FROM pg_stat_activity
    WHERE pid <> pg_backend_pid()
      AND query ILIKE '%REFRESH MATERIALIZED VIEW%asset_risk%';
END $$;

SET LOCAL lock_timeout = '60s';

DROP MATERIALIZED VIEW IF EXISTS asset_risk;

-- Body identical to 20260610 except the four exposure CTEs
-- (exposed_clusters, image_internet_exposed, image_exposed_spread,
-- cluster_exposed_vulns) read publicly_exposed_digests instead of
-- exposed_digests.
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
    FROM publicly_exposed_digests ed
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
        COUNT(DISTINCT rvc.canonical_id) FILTER (WHERE rvc.severity = 'MEDIUM')::bigint   AS medium_count,
        COUNT(DISTINCT rvc.canonical_id) FILTER (WHERE rvc.severity = 'LOW')::bigint      AS low_count,
        COUNT(DISTINCT rvc.canonical_id) FILTER (WHERE k.cve_id IS NOT NULL)::bigint      AS kev_count,
        COUNT(DISTINCT rvc.canonical_id) FILTER (
            WHERE k.cve_id IS NOT NULL AND rvc.fixed_version <> ''
        )::bigint                                                                          AS kev_fixable_count,
        COUNT(DISTINCT rvc.canonical_id) FILTER (
            WHERE k.cve_id IS NOT NULL AND k.known_ransomware
        )::bigint                                                                          AS kev_ransomware_count,
        COALESCE(BOOL_OR(k.due_date < CURRENT_DATE), false)                               AS kev_due_passed,
        COALESCE(MAX(e.score) FILTER (WHERE k.cve_id IS NOT NULL), 0)::real               AS kev_epss_max,
        BOOL_OR(rvc.severity = 'CRITICAL' AND rvc.fixed_version <> '')                    AS has_fix_for_critical,
        BOOL_OR(rvc.severity = 'HIGH' AND rvc.fixed_version <> '')                        AS has_fix_for_high,
        MAX(rvc.scanned_at)                                                               AS last_scan_at
    FROM repo_vuln_canonical rvc
    LEFT JOIN cisa_kev_entries k ON k.cve_id = rvc.canonical_id
    LEFT JOIN epss_entries e     ON e.cve_id = rvc.canonical_id
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
    -- and aggregate.
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
        COALESCE(rdh.major_behind_direct, 0)::bigint    AS major_behind_dep_count,
        COALESCE(rva.medium_count, 0)::bigint           AS medium_count,
        COALESCE(rva.low_count, 0)::bigint              AS low_count,
        COALESCE(rva.has_fix_for_high, false)           AS has_fix_for_high,
        COALESCE(rva.kev_fixable_count, 0)::bigint      AS kev_fixable_count,
        COALESCE(rva.kev_ransomware_count, 0)::bigint   AS kev_ransomware_count,
        COALESCE(rva.kev_due_passed, false)             AS kev_due_passed,
        COALESCE(rva.kev_epss_max, 0)::real             AS kev_epss_max,
        0::bigint                                       AS exposed_kev_count,
        0::bigint                                       AS exposed_critical_count,
        0::real                                         AS exposed_epss_max,
        0::bigint                                       AS cluster_count,
        0::bigint                                       AS exposed_cluster_count
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
        COUNT(DISTINCT ivc.canonical_id) FILTER (WHERE ivc.severity = 'MEDIUM')::bigint   AS medium_count,
        COUNT(DISTINCT ivc.canonical_id) FILTER (WHERE ivc.severity = 'LOW')::bigint      AS low_count,
        COUNT(DISTINCT ivc.canonical_id) FILTER (WHERE k.cve_id IS NOT NULL)::bigint      AS kev_count,
        COUNT(DISTINCT ivc.canonical_id) FILTER (
            WHERE k.cve_id IS NOT NULL AND ivc.fixed_version <> ''
        )::bigint                                                                          AS kev_fixable_count,
        COUNT(DISTINCT ivc.canonical_id) FILTER (
            WHERE k.cve_id IS NOT NULL AND k.known_ransomware
        )::bigint                                                                          AS kev_ransomware_count,
        COALESCE(BOOL_OR(k.due_date < CURRENT_DATE), false)                               AS kev_due_passed,
        COALESCE(MAX(e.score) FILTER (WHERE k.cve_id IS NOT NULL), 0)::real               AS kev_epss_max,
        BOOL_OR(ivc.severity = 'CRITICAL' AND ivc.fixed_version <> '')                    AS has_fix_for_critical,
        BOOL_OR(ivc.severity = 'HIGH' AND ivc.fixed_version <> '')                        AS has_fix_for_high,
        MAX(ivc.scanned_at)                                                               AS last_scan_at
    FROM image_vuln_canonical ivc
    LEFT JOIN cisa_kev_entries k ON k.cve_id = ivc.canonical_id
    LEFT JOIN epss_entries e     ON e.cve_id = ivc.canonical_id
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
    SELECT DISTINCT digest FROM publicly_exposed_digests
),
-- Deployment spread: how many clusters run each digest, and in how
-- many of them the digest is reachable from the internet. The fix is
-- one image rebuild; the rollout is cluster_count redeploys.
image_cluster_spread AS (
    SELECT digest, COUNT(DISTINCT cluster_id)::bigint AS cluster_count
    FROM cluster_digests
    GROUP BY digest
),
image_exposed_spread AS (
    SELECT digest, COUNT(DISTINCT cluster_id)::bigint AS exposed_cluster_count
    FROM publicly_exposed_digests
    GROUP BY digest
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
        COALESCE(idh.major_behind_direct, 0)::bigint    AS major_behind_dep_count,
        COALESCE(iva.medium_count, 0)::bigint           AS medium_count,
        COALESCE(iva.low_count, 0)::bigint              AS low_count,
        COALESCE(iva.has_fix_for_high, false)           AS has_fix_for_high,
        COALESCE(iva.kev_fixable_count, 0)::bigint      AS kev_fixable_count,
        COALESCE(iva.kev_ransomware_count, 0)::bigint   AS kev_ransomware_count,
        COALESCE(iva.kev_due_passed, false)             AS kev_due_passed,
        COALESCE(iva.kev_epss_max, 0)::real             AS kev_epss_max,
        -- Digest is the exposure unit, so the exposed_* projections
        -- are exact: every vuln on an exposed digest is exposed.
        CASE WHEN iie.digest IS NOT NULL
             THEN COALESCE(iva.kev_count, 0) ELSE 0 END::bigint
                                                        AS exposed_kev_count,
        CASE WHEN iie.digest IS NOT NULL
             THEN COALESCE(iva.critical_count, 0) ELSE 0 END::bigint
                                                        AS exposed_critical_count,
        CASE WHEN iie.digest IS NOT NULL
             THEN COALESCE(iem.epss_max, 0) ELSE 0 END::real
                                                        AS exposed_epss_max,
        COALESCE(ics.cluster_count, 0)::bigint          AS cluster_count,
        COALESCE(ies.exposed_cluster_count, 0)::bigint  AS exposed_cluster_count
    FROM image_digests d
    JOIN (SELECT DISTINCT digest FROM cluster_digests) cd ON cd.digest = d.digest
    LEFT JOIN image_vuln_agg     iva ON iva.image_id = d.id::text
    LEFT JOIN image_epss_max     iem ON iem.image_id = d.id::text
    LEFT JOIN image_last_scan    ils ON ils.image_id = d.id
    LEFT JOIN image_dep_health   idh ON idh.image_id = d.id
    LEFT JOIN image_has_sbom     ihs ON ihs.image_id = d.id
    LEFT JOIN image_internet_exposed iie ON iie.digest = d.digest
    LEFT JOIN image_cluster_spread   ics ON ics.digest = d.digest
    LEFT JOIN image_exposed_spread   ies ON ies.digest = d.digest
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
        MAX(ivc.scanned_at)                 AS last_scan_at,
        -- KEV facts are constant per canonical_id; BOOL_OR collapses
        -- the per-finding duplicates without needing k.* in GROUP BY.
        COALESCE(BOOL_OR(k.cve_id IS NOT NULL), false)                              AS kev,
        COALESCE(BOOL_OR(k.cve_id IS NOT NULL AND ivc.fixed_version <> ''), false)  AS kev_fixable,
        COALESCE(BOOL_OR(k.known_ransomware), false)                                AS kev_ransomware,
        COALESCE(BOOL_OR(k.due_date < CURRENT_DATE), false)                         AS kev_due_passed
    FROM cluster_digests cd
    JOIN image_digests d          ON d.digest    = cd.digest
    JOIN image_vuln_canonical ivc ON ivc.image_id = d.id::text
    LEFT JOIN cisa_kev_entries k  ON k.cve_id     = ivc.canonical_id
    GROUP BY cd.cluster_id, ivc.canonical_id
),
-- Exact per-cluster exposure aggregation: only vulns carried by a
-- digest that is itself internet-exposed in that cluster. Replaces
-- the v1 approximation where cluster-level kev_count + the
-- internet_exposed boolean could conflate a KEV on a non-exposed
-- image with an exposed-but-clean one.
cluster_exposed_vulns AS (
    SELECT
        ed.cluster_id,
        COUNT(DISTINCT ivc.canonical_id) FILTER (WHERE k.cve_id IS NOT NULL)::bigint      AS exposed_kev_count,
        COUNT(DISTINCT ivc.canonical_id) FILTER (WHERE ivc.severity = 'CRITICAL')::bigint AS exposed_critical_count,
        COALESCE(MAX(e.score), 0)::real                                                   AS exposed_epss_max
    FROM publicly_exposed_digests ed
    JOIN image_digests d          ON d.digest     = ed.digest
    JOIN image_vuln_canonical ivc ON ivc.image_id = d.id::text
    LEFT JOIN cisa_kev_entries k  ON k.cve_id     = ivc.canonical_id
    LEFT JOIN epss_entries e      ON e.cve_id     = ivc.canonical_id
    GROUP BY ed.cluster_id
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
        COUNT(*) FILTER (WHERE cc.kev)::bigint                             AS kev_count,
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
        COALESCE(cdh.major_behind_count, 0)::bigint                        AS major_behind_dep_count,
        COUNT(*) FILTER (WHERE cc.sev_rank = 3)::bigint                    AS medium_count,
        COUNT(*) FILTER (WHERE cc.sev_rank = 4)::bigint                    AS low_count,
        COALESCE(BOOL_OR(cc.sev_rank = 2 AND cc.any_fixed), false)         AS has_fix_for_high,
        COUNT(*) FILTER (WHERE cc.kev_fixable)::bigint                     AS kev_fixable_count,
        COUNT(*) FILTER (WHERE cc.kev_ransomware)::bigint                  AS kev_ransomware_count,
        COALESCE(BOOL_OR(cc.kev_due_passed), false)                        AS kev_due_passed,
        COALESCE(MAX(e.score) FILTER (WHERE cc.kev), 0)::real              AS kev_epss_max,
        COALESCE(cev.exposed_kev_count, 0)::bigint                         AS exposed_kev_count,
        COALESCE(cev.exposed_critical_count, 0)::bigint                    AS exposed_critical_count,
        COALESCE(cev.exposed_epss_max, 0)::real                            AS exposed_epss_max,
        0::bigint                                                          AS cluster_count,
        0::bigint                                                          AS exposed_cluster_count
    FROM (SELECT DISTINCT cluster_id FROM cluster_digests) c
    LEFT JOIN cluster_canonical  cc ON cc.cluster_id = c.cluster_id
    LEFT JOIN epss_entries        e ON e.cve_id      = cc.canonical_id
    LEFT JOIN cluster_dep_health cdh ON cdh.cluster_id = c.cluster_id
    LEFT JOIN exposed_clusters   ec ON ec.cluster_id   = c.cluster_id
    LEFT JOIN cluster_exposed_vulns cev ON cev.cluster_id = c.cluster_id
    GROUP BY c.cluster_id, cdh.worst_score, cdh.archived_count,
             cdh.deprecated_count, cdh.max_major_behind,
             cdh.major_behind_count, ec.cluster_id,
             cev.exposed_kev_count, cev.exposed_critical_count,
             cev.exposed_epss_max
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
