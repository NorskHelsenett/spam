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
-- selector matches the Container's pod_labels, and a routing object
-- pointing at that Service's name. Two backend-ref shapes are stored
-- in cluster_record:
--
--   shape A: data.rules[].paths[].backend_name   — k8s Ingress
--   shape B: data.backends[].name                — Traefik IngressRoute /
--                                                  IngressRouteTCP, plus
--                                                  Gateway HTTPRoute /
--                                                  GRPCRoute / TLSRoute
--
-- Mirrors HostChainHandler's traversal in scam/handler.go.
exposed_digests AS (
    -- shape A: k8s Ingress
    SELECT DISTINCT
        cont.data->>'digest'     AS digest,
        cont.data->>'cluster_id' AS cluster_id
    FROM cluster_record ing
    JOIN cluster_record svc
      ON svc.data->>'kind'       = 'Service'
     AND svc.data->>'cluster_id' = ing.data->>'cluster_id'
     AND svc.data->>'namespace'  = ing.data->>'namespace'
     AND COALESCE(svc.data->>'msg', '') <> 'DELETE'
     AND jsonb_typeof(ing.data->'rules') = 'array'
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
     AND COALESCE(cont.data->>'msg', '')    <> 'DELETE'
    WHERE ing.data->>'kind' = 'Ingress'
      AND COALESCE(ing.data->>'msg', '') <> 'DELETE'

    UNION

    -- shape B: IngressRoute / IngressRouteTCP (Traefik) and
    -- HTTPRoute / GRPCRoute / TLSRoute (Gateway API). Each stores
    -- backends as data.backends[].name.
    SELECT DISTINCT
        cont.data->>'digest'     AS digest,
        cont.data->>'cluster_id' AS cluster_id
    FROM cluster_record ing
    JOIN cluster_record svc
      ON svc.data->>'kind'       = 'Service'
     AND svc.data->>'cluster_id' = ing.data->>'cluster_id'
     AND svc.data->>'namespace'  = ing.data->>'namespace'
     AND COALESCE(svc.data->>'msg', '') <> 'DELETE'
     AND jsonb_typeof(ing.data->'backends') = 'array'
     AND EXISTS (
         SELECT 1
           FROM jsonb_array_elements(ing.data->'backends') AS b
          WHERE b->>'name' = svc.data->>'name'
     )
    JOIN cluster_record cont
      ON cont.data->>'kind'       = 'Container'
     AND cont.data->>'cluster_id' = svc.data->>'cluster_id'
     AND cont.data->>'namespace'  = svc.data->>'namespace'
     AND (cont.data->'pod_labels') @> (svc.data->'selector')
     AND COALESCE(cont.data->>'digest', '') <> ''
     AND COALESCE(cont.data->>'msg', '')    <> 'DELETE'
    WHERE ing.data->>'kind' IN
            ('IngressRoute','IngressRouteTCP','HTTPRoute','GRPCRoute','TLSRoute')
      AND COALESCE(ing.data->>'msg', '') <> 'DELETE'
),

-- ---------- chain: cluster → digests currently running ----------
-- "Currently running" rather than "ever observed":
--   * msg <> 'DELETE'  drops tombstoned pods
--
-- We deliberately do NOT gate on received_at: the scam ingest
-- pipeline emits Container records on observed create/delete events,
-- not as a periodic heartbeat, so a stable pod that has been running
-- unchanged for weeks carries a stale received_at while still being
-- alive. Trusting msg<>'DELETE' means we may slightly over-count if a
-- delete event is missed (controller restart, dropped watch); that's
-- an acceptable trade vs. dramatically under-counting long-running
-- workloads.
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
-- Surface the canonical_id from vuln_metadata so KEV/EPSS hit even
-- when the scanner stored a non-CVE alias. VEX overrides with status
-- 'not_affected' or 'fixed' are filtered out here so triage threat
-- counts honour the operator's manual call. VEX is keyed on
-- (purl, vuln_id) — we bridge to the unified row's asset via
-- sbom_component_view ↔ sbom_bindings, so the filter only fires for
-- assets that actually carry a VEX'd PURL in their SBOM.
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
-- A cluster is "internet exposed" only when it has at least one digest
-- that is both internet-reachable (per exposed_digests) and carries an
-- actionable vulnerability finding. This makes the +30 KEV-and-exposed
-- tier bonus mean "exploitable AND reachable" instead of the looser
-- "exploitable AND there's an Ingress somewhere in the cluster" — clean
-- exposed workloads correctly stop flipping the cluster row to red.
-- Defined after image_vuln_canonical because the predicate joins
-- through it.
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
        EXTRACT(DAY FROM NOW() - COALESCE(sa.last_scan_at, NOW() - INTERVAL '999 days'))::int
                                                        AS scan_age_days,
        sa.last_scan_at                                 AS last_scan_at,
        EXISTS (SELECT 1 FROM sbom_bindings sb
                JOIN repo_commits rc ON rc.id = sb.asset_ref_id
                WHERE sb.asset_type = 'REPO_COMMIT' AND rc.repo_id = r.id) AS has_sbom,
        -- Dep-health rollup (Phase 3): worst score across the repo's
        -- direct deps, plus counts of archived/deprecated direct deps,
        -- plus how many direct deps are at least one major version
        -- behind. Default values reflect "no penalty observed" so a
        -- repo with no measured deps isn't downgraded.
        COALESCE(dh.worst_score, 100)::real             AS worst_dep_health_score,
        COALESCE(dh.archived_direct, 0)::bigint         AS archived_dep_count,
        COALESCE(dh.deprecated_direct, 0)::bigint       AS deprecated_dep_count,
        COALESCE(dh.max_major_behind, 0)::int           AS max_major_behind,
        COALESCE(dh.major_behind_direct, 0)::bigint     AS major_behind_dep_count
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
    -- Last scan time, derived from the actual scan-record tables so
    -- a clean repo (zero vuln rows) doesn't look stale. SBOM scans
    -- and gitleaks runs both tell us "the asset was looked at on
    -- this date"; we take the most recent of the two so the freshness
    -- threshold reflects whichever ran last.
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
            COUNT(*) FILTER (WHERE d.is_deprecated AND md.direct)::bigint                AS deprecated_direct,
            -- Worst major-version lag across direct deps. Zero
            -- when nothing is behind; major>=1 means at least one
            -- direct dep is a full major release behind.
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
        EXTRACT(DAY FROM NOW() - COALESCE(isa.last_scan_at, NOW() - INTERVAL '999 days'))::int
                                                        AS scan_age_days,
        isa.last_scan_at                                AS last_scan_at,
        EXISTS (SELECT 1 FROM sbom_bindings sb
                WHERE sb.asset_type = 'IMAGE_DIGEST' AND sb.asset_ref_id = d.id) AS has_sbom,
        -- Dep-health rollup at the image level. Images carry their
        -- own SBOM (sbom_bindings asset_type='IMAGE_DIGEST') with
        -- manifest_dependencies, so the same chain that scores a
        -- repo's deps applies here. Useful for images built outside
        -- the org's repo set (e.g. third-party base images) where
        -- there's no source-repo to score otherwise.
        COALESCE(idh.worst_score, 100)::real            AS worst_dep_health_score,
        COALESCE(idh.archived_direct, 0)::bigint        AS archived_dep_count,
        COALESCE(idh.deprecated_direct, 0)::bigint      AS deprecated_dep_count,
        COALESCE(idh.max_major_behind, 0)::int          AS max_major_behind,
        COALESCE(idh.major_behind_direct, 0)::bigint    AS major_behind_dep_count
    -- INNER JOIN to the in-cluster digest set up front (rather than
    -- a trailing WHERE EXISTS) so the LATERALs below only fire for
    -- images we actually surface — vs. running them across every
    -- digest the system has ever seen and filtering at the end.
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
    -- Last scan time straight from image_scan_runs so a clean image
    -- (zero findings) doesn't look stale.
    LEFT JOIN LATERAL (
        SELECT MAX(isr.finished_at) AS last_scan_at
        FROM image_scan_runs isr
        WHERE isr.image_digest_id = d.id
          AND isr.finished_at IS NOT NULL
    ) isa ON TRUE
    -- Image dep-health: image SBOMs land in sbom_component_view
    -- (PURL-keyed, populated by syft/trivy at scan time) rather
    -- than manifest_dependencies (repo-side, sourced from manifest
    -- files). The PURL "kind" maps almost directly to dep_health's
    -- ecosystem column except for two ecosystems where the
    -- conventions diverge (golang↔go, gem↔rubygems). The CASE
    -- normalises that without needing a side-table.
    --
    -- All non-root SBOM components are treated as "direct" at the
    -- image level — operationally they're all baked into the
    -- image, the manifest_dependencies direct-vs-transitive
    -- distinction doesn't carry across the build boundary.
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
    -- (The cluster-presence gate is now the INNER JOIN to
    -- cluster_digests above; pre-deployment / retired images stay
    -- visible on /app/images for audit but skip the triage LATERALs
    -- entirely.)
),

-- ---------- cluster-side aggregation ----------
-- One row per (cluster, canonical_id) — the same advisory is counted
-- once per cluster regardless of how many images carry it. Worst
-- severity wins so a CVE reported as MEDIUM in one image and HIGH in
-- another contributes a single HIGH row to the cluster's tally.
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

-- Roll cluster_canonical up to the cluster row. KEV is a count of
-- distinct cluster CVEs that are also in CISA KEV. epss_max is the
-- worst score across the cluster's CVEs. Because cluster_canonical
-- is already (cluster, canonical) deduped, the LEFT JOIN to
-- epss_entries cannot multiply rows.
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
        -- Cluster dep-health inherits from the images running
        -- there. Computed as a single per-cluster aggregate via
        -- the cluster_dh LATERAL below so it doesn't multiply rows
        -- against the cluster_canonical join above.
        COALESCE(cluster_dh.worst_score, 100)::real                        AS worst_dep_health_score,
        COALESCE(cluster_dh.archived_count, 0)::bigint                     AS archived_dep_count,
        COALESCE(cluster_dh.deprecated_count, 0)::bigint                   AS deprecated_dep_count,
        COALESCE(cluster_dh.max_major_behind, 0)::int                      AS max_major_behind,
        COALESCE(cluster_dh.major_behind_count, 0)::bigint                 AS major_behind_dep_count
    FROM (SELECT DISTINCT cluster_id FROM cluster_digests) c
    LEFT JOIN cluster_canonical cc ON cc.cluster_id = c.cluster_id
    LEFT JOIN epss_entries e       ON e.cve_id     = cc.canonical_id
    -- Cluster dep-health: aggregate across every image running in
    -- the cluster. Walks cluster_digests → image_digests →
    -- sbom_component_view → dep_health using the same PURL kind ↔
    -- ecosystem mapping as image_signals.idh. Returns one row per
    -- cluster_id; nothing to multiply.
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
