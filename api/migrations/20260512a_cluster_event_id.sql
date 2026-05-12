-- 20260512a_cluster_event_id.sql
--
-- Per-record event_id and per-cluster last_seen_event_id used by the
-- ACK-driven reconcile path. SCAM agents stamp every emitted record
-- with a monotonic event_id (reset to 0 each process start); SPAM
-- advances cluster_sessions.last_seen_event_id as records ingest and
-- returns the current value in the push response. SCAM compares to
-- the highest event_id it just pushed, and fires a reconcile snapshot
-- on mismatch.
--
-- event_id on cluster_record is nullable because not every SCAM
-- emitter sends it (older agents, log lines without a SCAM-record
-- shape); a missing event_id contributes nothing to the per-cluster
-- counter advancement.

ALTER TABLE cluster_record
    ADD COLUMN IF NOT EXISTS event_id BIGINT;

CREATE INDEX IF NOT EXISTS ix_cluster_record_event_id
    ON cluster_record (event_id)
    WHERE event_id IS NOT NULL;

ALTER TABLE cluster_sessions
    ADD COLUMN IF NOT EXISTS last_seen_event_id BIGINT NOT NULL DEFAULT 0;
