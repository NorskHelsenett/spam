-- Replace ux_sbom_component_mv with a plain-column unique index.
--
-- REFRESH MATERIALIZED VIEW CONCURRENTLY requires at least one unique
-- index that uses only column names — no expressions, no WHERE clause.
-- The previous index wrapped the nullable columns in COALESCE(.., ''),
-- which disqualified it, so CONCURRENTLY always failed with SQLSTATE
-- 55000 on this view. That was masked while refreshView silently fell
-- back to a plain (blocking) refresh; now that the fallback is refused
-- on populated views, the component view never refreshes in the
-- background and goes stale until a restart. sbom_metadata_view got
-- the plain-column fix in 20260310; this view was missed.
--
-- NULLS NOT DISTINCT (Postgres 15+) reproduces what the COALESCE was
-- standing in for: the view body dedupes with DISTINCT ON
-- (sbom_id, asset_type, asset_ref_id, component_ref), which treats
-- NULLs as equal, so the index must too. component_ref is genuinely
-- nullable (components with neither bom-ref nor purl).
--
-- DROP + CREATE run in one transaction (EnsureViews wraps each file),
-- so concurrent refreshes on other replicas never observe the view
-- without a unique index.
--
-- NOTE: this migration runs once (hash-gated). If the 20260311 view
-- definition is ever re-applied — edited, or replayed by EnsureViews'
-- missing-matview recovery — it recreates the COALESCE index. The
-- EnsureSbomComponentViewIndex guard (internal/db/views.go) re-asserts
-- the plain-column index on every boot to cover that; keep the two in
-- sync if the index shape ever changes.

DROP INDEX IF EXISTS ux_sbom_component_mv;

CREATE UNIQUE INDEX ux_sbom_component_mv
  ON sbom_component_view (sbom_id, asset_type, asset_ref_id, component_ref)
  NULLS NOT DISTINCT;
