-- Trigram indexes that the /api/dependencies search predicate can
-- actually use. The existing idx_sbom_component_mv_pkg_trgm covers
-- ILIKE on package_name, but UnifiedDependenciesHandler filters on
-- COALESCE(package_name, normalized_name, name) — that expression
-- doesn't match the simple-column index, so the planner falls back
-- to a seq scan over the full materialised view (slow on `?q=spa`).
--
-- Replace with a functional trigram index over the same COALESCE so
-- the index applies regardless of which column populates the value.
-- Manifest dependencies get a trigram on `name` for the same reason.

CREATE EXTENSION IF NOT EXISTS pg_trgm;

DROP INDEX IF EXISTS idx_sbom_component_mv_pkg_trgm;

CREATE INDEX IF NOT EXISTS idx_sbom_component_mv_search_trgm
    ON sbom_component_view
    USING gin (COALESCE(package_name, normalized_name, name) gin_trgm_ops)
    WHERE COALESCE(package_name, normalized_name, name) IS NOT NULL;

-- The default-source search also accepts purl matches (`scv.purl ILIKE ?`);
-- without a trigram index that branch falls back to a seq scan even when
-- the name branch is fast.
CREATE INDEX IF NOT EXISTS idx_sbom_component_mv_purl_trgm
    ON sbom_component_view
    USING gin (purl gin_trgm_ops)
    WHERE purl IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_manifest_dependencies_name_trgm
    ON manifest_dependencies
    USING gin (name gin_trgm_ops);
