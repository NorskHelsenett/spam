-- Performance indexes for the asset_risk MV refresh path.
--
-- Without these, refresh time scales with the *product* of two large
-- inputs:
--
--   per-image dep-health LATERAL  =  images × sbom_component_view
--   per-row cluster-presence EXISTS = image_digests × Container records
--
-- On a 500-finding cluster the refresh measured at ~15 min wall-clock;
-- both lookups are sequential scans because no usable index exists for
-- the predicate shape.
--
-- 1. Container-digest lookup. Used by:
--    * cluster_digests CTE in asset_risk
--    * exposed_digests CTE
--    * imageDigestRunningInCluster() in assets/image.go (UpsertImageDigest gate)
--    * image_signals' WHERE EXISTS (cluster_digests)
--
--    Partial index keeps it small: only Container rows with a non-empty
--    digest match the relevant predicates.
CREATE INDEX IF NOT EXISTS idx_cluster_record_container_digest
  ON cluster_record ((data->>'digest'))
  WHERE data->>'kind' = 'Container'
    AND COALESCE(data->>'digest', '') <> '';

-- 2. Image SBOM-component lookup. Used by:
--    * image dep-health LATERAL (idh) in image_signals
--    * VEX bridge join (sbom_component_view × component_vex)
--
--    sbom_component_view is a materialized view; indexes survive
--    REFRESH MATERIALIZED VIEW (CONCURRENTLY) but are rebuilt at
--    REFRESH time, which is fine — these are small relative to the MV.
--    asset_ref_id leads so per-image lookups become an index seek;
--    package_name + kind cover the join to dep_health without a heap
--    visit.
CREATE INDEX IF NOT EXISTS idx_sbom_component_mv_image_asset
  ON sbom_component_view (asset_ref_id, package_name, kind)
  WHERE asset_type = 'IMAGE_DIGEST' AND is_root = false;
