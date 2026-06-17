-- 20260610a_mv_refresh_source_version.sql
--
-- Source-change fingerprints for materialized-view refreshes.
--
-- pg_stat_statements showed the MV families rebuilding at their
-- debounce floor around the clock: ingest never stops, every ingest
-- fires TriggerRefresh, and the debounce window only rate-limits the
-- rebuilds — it never asks whether the source data actually changed.
-- The tombstone UPDATE ran tens of thousands of times while touching
-- a few thousand rows total, i.e. most ingest cycles change nothing,
-- yet cluster_summary/cluster_image_inventory rebuilt every window and
-- exposed_digests/asset_risk every 5 minutes, 24/7.
--
-- source_version stores a cheap fingerprint of the family's source
-- tables (e.g. max(cluster_record.last_change_at)) captured just
-- before the last refresh. A trigger that finds the fingerprint
-- unchanged bumps refreshed_at and skips the rebuild entirely.

ALTER TABLE materialized_view_refreshes
    ADD COLUMN IF NOT EXISTS source_version TEXT NOT NULL DEFAULT '';

-- Backs SELECT max(last_change_at) FROM cluster_record — the cluster /
-- host-exposure family fingerprint — as a backwards index scan instead
-- of a 3.5M-row aggregate.
CREATE INDEX IF NOT EXISTS ix_cluster_record_last_change_at
    ON cluster_record (last_change_at);
