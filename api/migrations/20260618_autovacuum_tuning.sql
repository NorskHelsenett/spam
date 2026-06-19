-- Per-table autovacuum tuning for the two highest-churn tables.
--
-- Run by EnsureViews inside a transaction. ALTER TABLE ... SET (storage
-- params) takes only a SHARE UPDATE EXCLUSIVE lock (it does not block
-- reads or writes), so it is safe to apply automatically on a live table.

-- jobs: append-heavy (one row per VULN_META_FETCH, IMAGE_SCAN, REFRESH_MV
-- tick, ...) with constant status UPDATEs. The default 20% scale factor
-- means autovacuum effectively never triggers once the table is large, so
-- dead tuples accumulate well past the live count. With the PRUNE_JOBS
-- sweep now deleting terminal rows on a schedule, a lower scale factor
-- lets autovacuum reclaim the dead tuples those deletes (and the status
-- churn) create.
ALTER TABLE jobs SET (
  autovacuum_vacuum_scale_factor = 0.05,
  autovacuum_analyze_scale_factor = 0.02,
  autovacuum_vacuum_threshold = 1000
);

-- cluster_record: the highest-churn table in the system — continuous agent
-- UPDATEs, far more than INSERTs. At the default 20% scale factor
-- autovacuum fires only after a huge dead-tuple backlog and then runs for
-- many minutes, falling permanently behind and competing for I/O with the
-- MV refreshes. A 5% vacuum / 10% analyze scale factor keeps the table far
-- leaner so each vacuum cycle is cheaper and bloat stops compounding.
ALTER TABLE cluster_record SET (
  autovacuum_vacuum_scale_factor = 0.05,
  autovacuum_analyze_scale_factor = 0.1,
  autovacuum_vacuum_threshold = 1000
);
