-- Fix the cluster_record digest lookup so it uses an index instead of a
-- full parallel sequential scan over the whole table.
--
-- The triage-image cluster panel and the vuln-detail cluster-presence
-- query both filter:
--
--   WHERE data->>'kind' = 'Container' AND data->>'digest' = $1 ...
--
-- with the digest passed as a BIND PARAMETER. The existing partial index
-- idx_cluster_record_container_digest (migration 20260507d) carries the
-- predicate:
--
--   WHERE data->>'kind' = 'Container'
--     AND COALESCE(data->>'digest', '') <> ''
--
-- Postgres can only use a partial index when it can PROVE the index
-- predicate is implied by the query's WHERE. It proves kind='Container'
-- (a literal), but it cannot prove COALESCE($1,'') <> '' for an unknown
-- parameter at plan time -- so it discards the index and seq-scans all
-- ~4M rows to return a handful. Measured at ~17s / ~3.9GB read in prod.
--
-- The COALESCE(...) <> '' term buys nothing for an equality lookup
-- (digest = $1 can never match an empty digest) but makes the index
-- unusable. This index keeps only the provable predicate, so the
-- parameterized equality becomes an index scan.
--
-- CONCURRENTLY: build without locking the heavily-written cluster_record
-- table. Must run outside a transaction block.

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_cluster_record_container_digest_v2
  ON cluster_record ((data->>'digest'))
  WHERE data->>'kind' = 'Container';

-- The old index is now redundant for these lookups. Drop after the new
-- one is confirmed in use (kept here, commented, to make the intent
-- explicit without coupling the two operations in one deploy):
-- DROP INDEX CONCURRENTLY IF EXISTS idx_cluster_record_container_digest;
