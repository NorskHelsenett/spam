-- Composite index on (name, ecosystem) to support GROUP BY and WHERE filters
-- in unified dependency queries. The existing single-column indexes on name and
-- ecosystem separately do not help aggregation queries that group by both columns.
CREATE INDEX IF NOT EXISTS idx_manifest_dependencies_name_ecosystem
  ON manifest_dependencies (name, ecosystem);
