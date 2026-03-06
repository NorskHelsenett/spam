-- Speeds up dependency assets endpoint lookups that filter by
-- ecosystem + coalesced package name and optional version.
CREATE INDEX IF NOT EXISTS idx_sbom_component_mv_deps_coalesced_name
  ON sbom_component_view (
    kind,
    (COALESCE(package_name, normalized_name, name)),
    purl_version,
    sbom_id,
    asset_type,
    asset_ref_id
  )
  WHERE is_root = false AND purl IS NOT NULL;

-- Helps manifest-side dependency asset lookups with optional version filter.
CREATE INDEX IF NOT EXISTS idx_manifest_dependencies_name_ecosystem_version_manifest
  ON manifest_dependencies (name, ecosystem, version, manifest_id);
