-- Enable pg_trgm for trigram-based fuzzy search on repository names.
-- GIN indexes on slug and org allow both ILIKE '%pattern%' and the word
-- similarity operator (<%) to use index scans instead of sequential scans.
CREATE EXTENSION IF NOT EXISTS pg_trgm;

CREATE INDEX IF NOT EXISTS idx_repos_slug_trgm ON repos USING GIN (slug gin_trgm_ops);
CREATE INDEX IF NOT EXISTS idx_repos_org_trgm  ON repos USING GIN (org  gin_trgm_ops);
