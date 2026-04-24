-- Widen repo_commits with commit metadata captured by the runner.
--
-- The UI's repo page previously fetched the commit list live from the
-- provider API on every page load, capped at limit=10 in
-- ProviderRepoDetailsHandler. Both expensive (provider rate limit) and
-- wrong (author tally maxes at the sample size). The runner already
-- clones each commit it scans, so it's a free source of authoritative
-- metadata — git itself rather than the provider.
--
-- All columns are nullable: rows written by older runners (which only
-- populate repo_id/commit_sha/ref) stay as-is, and the UI filters to
-- commits that have been enriched.
--
-- `signed` mirrors git's %G? output (G/B/U/X/Y/R/E/N) verbatim so the UI
-- can render the exact signature state without re-interpreting.
ALTER TABLE repo_commits
    ADD COLUMN IF NOT EXISTS author_name  TEXT,
    ADD COLUMN IF NOT EXISTS author_email TEXT,
    ADD COLUMN IF NOT EXISTS author_date  TIMESTAMP WITH TIME ZONE,
    ADD COLUMN IF NOT EXISTS signed       VARCHAR(1),
    ADD COLUMN IF NOT EXISTS message      TEXT;

-- Drives the Commits tab list query (repo scope, newest first). Partial
-- index so unenriched legacy rows don't bloat the btree.
CREATE INDEX IF NOT EXISTS idx_repo_commits_author_date
    ON repo_commits (repo_id, author_date DESC)
    WHERE author_date IS NOT NULL;
