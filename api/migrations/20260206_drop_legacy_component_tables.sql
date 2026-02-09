-- Drop legacy normalized component tables that were replaced by sbom_component_view
-- These tables are no longer populated after the refactoring in commit a3675081a4

DROP TABLE IF EXISTS sbom_components;
DROP TABLE IF EXISTS component_dependencies;
DROP TABLE IF EXISTS component_versions;
DROP TABLE IF EXISTS components;
