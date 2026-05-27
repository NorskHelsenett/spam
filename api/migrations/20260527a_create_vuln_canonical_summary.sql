-- vuln_canonical_summary: one row per canonical_id with everything the
-- admin /api/vuln/list page needs — pre-joined to KEV / EPSS, the
-- assets array baked in, and the row count rolled up. Sit on top of
-- vuln_canonical_assets (the per-asset MV from 20260527).
--
-- Why this exists:
--   /api/vuln/list and /api/vuln/summary both do a full GROUP BY
--   canonical_id every request — at fleet scale that's tens of
--   thousands of rows being aggregated under each cache miss, and
--   the cache version turns over on every scan. This MV does the
--   group work once per refresh and exposes it under a btree that
--   matches the UI's ORDER BY tuple, so the admin list becomes an
--   index-ordered LIMIT scan.
--
-- Why admin-only:
--   The assets array is post-aggregation; ACL fragments need asset
--   grain to filter. Scoped (non-admin) callers stay on
--   vuln_canonical_assets, which is per-asset and ACL-filterable.

DROP MATERIALIZED VIEW IF EXISTS vuln_canonical_summary;

CREATE MATERIALIZED VIEW vuln_canonical_summary AS
WITH grouped AS (
    SELECT
        canonical_id,
        MIN(sev_rank)::int                                          AS sev_rank,
        -- Display fields picked from the worst-severity asset row,
        -- breaking ties by most-recent scan. Mirrors the existing
        -- LoadListPage `grouped` CTE picks, just sourced from the
        -- pre-aggregated canonical_assets layer (which itself picked
        -- the worst row per asset already, so any (sev_rank, scanned)
        -- ordering across assets re-establishes the same fan-out).
        (array_agg(severity          ORDER BY sev_rank ASC, last_scanned_at DESC NULLS LAST, asset_id ASC))[1] AS severity,
        (array_agg(pkg_name          ORDER BY sev_rank ASC, last_scanned_at DESC NULLS LAST, asset_id ASC))[1] AS pkg_name,
        (array_agg(installed_version ORDER BY sev_rank ASC, last_scanned_at DESC NULLS LAST, asset_id ASC))[1] AS installed_version,
        (array_agg(fixed_version     ORDER BY sev_rank ASC, last_scanned_at DESC NULLS LAST, asset_id ASC))[1] AS fixed_version,
        (array_agg(title             ORDER BY sev_rank ASC, last_scanned_at DESC NULLS LAST, asset_id ASC))[1] AS title,
        (array_agg(description       ORDER BY sev_rank ASC, last_scanned_at DESC NULLS LAST, asset_id ASC))[1] AS description,
        -- Sources across all assets, de-duped. canonical_assets already
        -- carries a jsonb sources column per asset; this flattens them.
        COALESCE(
            (SELECT jsonb_agg(DISTINCT s)
               FROM (
                 SELECT jsonb_array_elements(srcs) AS s
                 FROM unnest(array_agg(sources)) AS srcs
               ) t
               WHERE s IS NOT NULL),
            '[]'::jsonb
        )                                                            AS sources,
        -- Assets array as returned by /api/vuln/list. DISTINCT collapses
        -- the per-canonical_assets row → one entry per asset. No cap;
        -- response shape matches the existing handler's behavior.
        COALESCE(
            jsonb_agg(DISTINCT jsonb_build_object(
                'type',   asset_type,
                'id',     asset_id,
                'slug',   asset_slug,
                'digest', asset_digest
            )),
            '[]'::jsonb
        )                                                            AS assets,
        COUNT(*) FILTER (WHERE asset_type = 'repo')::int             AS repo_count,
        COUNT(*) FILTER (WHERE asset_type = 'image')::int            AS image_count,
        BOOL_OR(has_fix)                                             AS has_fix,
        MAX(cve_year)                                                AS cve_year,
        MAX(last_scanned_at)                                         AS last_scanned_at
    FROM vuln_canonical_assets
    GROUP BY canonical_id
)
SELECT
    g.canonical_id                                  AS vuln_id,
    g.sev_rank,
    g.severity,
    g.pkg_name,
    g.installed_version,
    g.fixed_version,
    g.title,
    g.description,
    g.sources,
    g.assets,
    g.repo_count,
    g.image_count,
    g.has_fix,
    g.cve_year,
    g.last_scanned_at,
    -- KEV / EPSS joined on canonical_id. Both feeds key on CVE-*; for
    -- non-CVE canonicals the LEFT JOIN leaves columns NULL (kev_known
    -- = FALSE, epss_score = 0.0), matching how the original LoadListPage
    -- query treated them.
    (kev.cve_id IS NOT NULL)                        AS kev_known,
    COALESCE(kev.known_ransomware, FALSE)           AS kev_known_ransomware,
    kev.date_added                                  AS kev_date_added,
    COALESCE(epss.score, 0)::float                  AS epss_score,
    COALESCE(epss.percentile, 0)::float             AS epss_percentile
FROM grouped g
LEFT JOIN cisa_kev_entries kev  ON kev.cve_id  = g.canonical_id
LEFT JOIN epss_entries     epss ON epss.cve_id = g.canonical_id
WITH NO DATA;

-- REFRESH CONCURRENTLY requirement.
CREATE UNIQUE INDEX idx_vuln_canonical_summary_unique
    ON vuln_canonical_summary (vuln_id);

-- The big one: btree matching the UI's ORDER BY tuple. Per-column
-- directions matter — sev_rank ASC (CRITICAL first), then kev DESC
-- (KEV-listed first), then epss DESC (worst score first), then cve_year
-- DESC (newest first), then vuln_id ASC for stability. With this in
-- place, /api/vuln/list LIMIT 50 OFFSET N becomes an ordered index
-- scan stopping at LIMIT, no sort step.
CREATE INDEX idx_vuln_canonical_summary_rank
    ON vuln_canonical_summary
       (sev_rank ASC, kev_known DESC, epss_score DESC, cve_year DESC NULLS LAST, vuln_id ASC);

-- Severity-only filter is the most common slicer; standalone index
-- keeps "show me Criticals" sub-page-fast without traversing the full
-- composite key.
CREATE INDEX idx_vuln_canonical_summary_sev
    ON vuln_canonical_summary (sev_rank);

-- KEV-only listing for the dashboard chips.
CREATE INDEX idx_vuln_canonical_summary_kev
    ON vuln_canonical_summary (kev_known) WHERE kev_known;

-- Fixable-only filter ("show me the ones we can actually fix today").
CREATE INDEX idx_vuln_canonical_summary_fixable
    ON vuln_canonical_summary (has_fix) WHERE has_fix;

-- Year filter — supports the /vuln list "CVE year" multiselect.
CREATE INDEX idx_vuln_canonical_summary_year
    ON vuln_canonical_summary (cve_year);
