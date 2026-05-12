-- 20260512_cluster_record_lifecycle_columns.sql
--
-- Promote lifecycle state out of the JSONB `data` column on
-- cluster_record. Today "is this row currently present in the cluster"
-- is encoded as `data->>'msg' = 'DELETE'`, which forces every reader
-- to JSONB-extract on every query, and which cannot express
-- "tombstoned by SCAM snapshot reconcile" distinctly from "DELETE
-- event arrived from an informer".
--
-- This migration adds first-class columns:
--   is_present       — true while the row reflects a live resource
--   first_seen_at    — when SPAM first observed this resource_key
--   last_change_at   — when the resource's state actually changed
--   tombstoned_at    — when is_present flipped to false (NULL until)
--   last_snapshot_id — most recent snapshot that touched this row
--
-- Dual-write strategy: ingest and snapshot-reconcile keep
-- data->>'msg' in sync (a snapshot tombstone overwrites msg to
-- 'DELETE'), so existing materialized views and queries that filter
-- on `data->>'msg' != 'DELETE'` continue to work unchanged. A later
-- migration will sweep them to `is_present = true` and drop the dual
-- write — at that point retention can also be tightened to purge
-- truly-tombstoned rows older than a configurable window.

ALTER TABLE cluster_record
    ADD COLUMN IF NOT EXISTS is_present BOOLEAN NOT NULL DEFAULT TRUE,
    ADD COLUMN IF NOT EXISTS first_seen_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS last_change_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS tombstoned_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS last_snapshot_id TEXT;

-- Backfill: existing DELETE-state rows become tombstones. Run once
-- under WHERE NULL guards so re-applying the migration is a no-op.
UPDATE cluster_record
SET is_present = FALSE,
    tombstoned_at = received_at
WHERE data->>'msg' = 'DELETE'
  AND tombstoned_at IS NULL;

UPDATE cluster_record
SET first_seen_at = received_at
WHERE first_seen_at IS NULL;

UPDATE cluster_record
SET last_change_at = received_at
WHERE last_change_at IS NULL;

ALTER TABLE cluster_record
    ALTER COLUMN first_seen_at SET NOT NULL,
    ALTER COLUMN last_change_at SET NOT NULL,
    ALTER COLUMN first_seen_at SET DEFAULT NOW(),
    ALTER COLUMN last_change_at SET DEFAULT NOW();

-- Partial index on the live filter so the eventual reader-sweep gets
-- an index lookup instead of JSONB extraction. Doesn't affect current
-- readers; harmless if dropped.
CREATE INDEX IF NOT EXISTS ix_cluster_record_is_present
    ON cluster_record (is_present)
    WHERE is_present = TRUE;

-- Index by snapshot for "what did snapshot X tombstone?" forensics.
CREATE INDEX IF NOT EXISTS ix_cluster_record_last_snapshot_id
    ON cluster_record (last_snapshot_id)
    WHERE last_snapshot_id IS NOT NULL;
