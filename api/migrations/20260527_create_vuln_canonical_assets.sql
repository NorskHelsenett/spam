-- vuln_canonical_assets: one row per (asset_type, asset_id, canonical_id).
--
-- Sits between the per-finding view_unified_*_vulnerabilities MVs and
-- the per-canonical vuln_canonical_summary MV. Three jobs:
--
--   1. Resolve canonical_id once (LEFT JOIN vuln_metadata) so request-
--      path queries don't repeat that join for every row.
--
--   2. Collapse alias / scanner variants of the same advisory on the
--      same asset (e.g. grype reports BIT-valkey-2025-49844 while OSV
--      reports CVE-2025-49844) into a single row at the worst
--      severity, mirroring the canonical-aware dedup LoadListPage
--      does in its `ranked` CTE today.
--
--   3. Carry the display fields (pkg_name, fixed_version, etc.)
--      picked from the worst-severity row so the downstream query
--      can skip ARRAY_AGG and just read columns.
--
-- The grain — one row per (asset, canonical) — is what makes this
-- usable by scoped (non-admin) callers: ACL filters at asset grain,
-- so anything coarser would lose the join column. Admins skip this
-- MV entirely and read vuln_canonical_summary (the next migration).

DROP MATERIALIZED VIEW IF EXISTS vuln_canonical_assets CASCADE;

CREATE MATERIALIZED VIEW vuln_canonical_assets AS
WITH unified AS (
    SELECT
        'repo'::text                                AS asset_type,
        v.repo_id                                   AS asset_id,
        v.repo_slug                                 AS asset_slug,
        ''::text                                    AS asset_digest,
        v.vuln_id,
        COALESCE(vm.canonical_id, v.vuln_id)        AS canonical_id,
        CASE v.severity
            WHEN 'CRITICAL' THEN 1
            WHEN 'HIGH'     THEN 2
            WHEN 'MEDIUM'   THEN 3
            WHEN 'LOW'      THEN 4
            ELSE 5
        END                                         AS sev_rank,
        v.severity,
        v.pkg_name,
        v.installed_version,
        v.fixed_version,
        v.title,
        v.description,
        v.source,
        v.scanned_at
    FROM view_unified_repositories_vulnerabilities v
    LEFT JOIN vuln_metadata vm ON vm.vuln_id = v.vuln_id
    UNION ALL
    SELECT
        'image'::text                               AS asset_type,
        v.image_id                                  AS asset_id,
        v.image_slug                                AS asset_slug,
        COALESCE(d.digest, '')                      AS asset_digest,
        v.vuln_id,
        COALESCE(vm.canonical_id, v.vuln_id)        AS canonical_id,
        CASE v.severity
            WHEN 'CRITICAL' THEN 1
            WHEN 'HIGH'     THEN 2
            WHEN 'MEDIUM'   THEN 3
            WHEN 'LOW'      THEN 4
            ELSE 5
        END                                         AS sev_rank,
        v.severity,
        v.pkg_name,
        v.installed_version,
        v.fixed_version,
        v.title,
        v.description,
        v.source,
        v.scanned_at
    FROM view_unified_image_vulnerabilities v
    LEFT JOIN image_digests d  ON d.id  = v.image_id
    LEFT JOIN vuln_metadata vm ON vm.vuln_id = v.vuln_id
)
SELECT
    asset_type,
    asset_id,
    -- asset_slug / asset_digest don't vary within (asset_type, asset_id);
    -- MAX is cheaper than carrying them in the GROUP BY key.
    MAX(asset_slug)                                                       AS asset_slug,
    MAX(asset_digest)                                                     AS asset_digest,
    canonical_id,
    -- Worst severity rank wins; matches the existing ranked CTE.
    MIN(sev_rank)::int                                                    AS sev_rank,
    -- Display fields: pick the value from the worst-severity row, then
    -- the most-recent scan, then deterministic source ordering. Same
    -- precedence the LoadListPage `grouped` CTE uses today, just done
    -- once at refresh time instead of once per request.
    (array_agg(severity          ORDER BY sev_rank ASC, scanned_at DESC NULLS LAST, source ASC))[1] AS severity,
    (array_agg(pkg_name          ORDER BY sev_rank ASC, scanned_at DESC NULLS LAST, source ASC))[1] AS pkg_name,
    (array_agg(installed_version ORDER BY sev_rank ASC, scanned_at DESC NULLS LAST, source ASC))[1] AS installed_version,
    (array_agg(fixed_version     ORDER BY sev_rank ASC, scanned_at DESC NULLS LAST, source ASC))[1] AS fixed_version,
    (array_agg(title             ORDER BY sev_rank ASC, scanned_at DESC NULLS LAST, source ASC))[1] AS title,
    (array_agg(description       ORDER BY sev_rank ASC, scanned_at DESC NULLS LAST, source ASC))[1] AS description,
    -- Per-asset source list. The summary MV jsonb_agg's across these
    -- to get the per-canonical source set; keeping the raw list here
    -- avoids re-scanning the unified MVs at summary refresh.
    COALESCE(
        (SELECT jsonb_agg(DISTINCT s) FROM unnest(array_agg(source)) AS s WHERE s IS NOT NULL AND s <> ''),
        '[]'::jsonb
    )                                                                     AS sources,
    -- Whether this (asset, canonical) has any row with a fix string.
    -- The summary MV's has_fix_for_critical / row-level fix predicates
    -- read this; keeping it boolean here avoids re-checking strings.
    BOOL_OR(fixed_version IS NOT NULL AND fixed_version <> '')            AS has_fix,
    -- Year extracted from canonical id ("<prefix>-YYYY-NNNN"). NULL when
    -- the prefix doesn't carry a year (e.g. GHSA-foo with no CVE alias
    -- yet enriched). Same regex computeSummary / LoadListPage use.
    NULLIF(substring(canonical_id from '-(\d{4})-'), '')::smallint        AS cve_year,
    -- Last-scanned across all rows in this group. Drives "as of" in
    -- the UI and is the dedup tie-breaker between (canonical, asset)
    -- rows on the per-summary jsonb_agg.
    MAX(scanned_at)                                                       AS last_scanned_at
FROM unified
GROUP BY asset_type, asset_id, canonical_id
WITH NO DATA;

-- REFRESH CONCURRENTLY requires a unique index. (asset_type, asset_id,
-- canonical_id) is the natural primary key — no two rows share it
-- after the GROUP BY collapses scanner variants.
CREATE UNIQUE INDEX idx_vuln_canonical_assets_unique
    ON vuln_canonical_assets (asset_type, asset_id, canonical_id);

-- Hot ACL-scan paths. Scoped LoadListPage and LoadSummaryScoped both
-- filter on (asset_type, asset_id) — the leading-column index lets
-- the planner pick an index scan over the small per-grant ID set
-- instead of a sequential scan of the MV.
CREATE INDEX idx_vuln_canonical_assets_repo
    ON vuln_canonical_assets (asset_id)
    WHERE asset_type = 'repo';
CREATE INDEX idx_vuln_canonical_assets_image
    ON vuln_canonical_assets (asset_id)
    WHERE asset_type = 'image';

-- Canonical-side lookup for the summary MV's join + alias resolution
-- in the detail handler. (canonical_id) also covers severity / KEV
-- filters in LoadListPage when no ACL is applied (admin path goes
-- straight to vuln_canonical_summary, but the canonical_id index is
-- cheap to keep).
CREATE INDEX idx_vuln_canonical_assets_canonical
    ON vuln_canonical_assets (canonical_id);

-- Sev-rank index for filter-by-severity admin scans (KEV-only,
-- critical-only, etc.) that don't go through the summary MV.
CREATE INDEX idx_vuln_canonical_assets_sev_rank
    ON vuln_canonical_assets (sev_rank);
