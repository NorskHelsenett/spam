-- Partial index covering the poller's "has this repo already had a
-- CREATE_RUN job finish?" check. pg_stat_statements surfaced this as
-- a high-call-count (1k+ per poll cycle) query — per-call cost was
-- ~7ms because the planner could only use idx_jobs_type and then had
-- to scan every CREATE_RUN row to filter by payload->>'repo_id'.
--
-- The existing ux_jobs_create_run_active_repo_commit unique index is
-- partial on status IN ('QUEUED','RETRY'); the poller is asking about
-- *finished* rows, so that index can't be used. This sibling partial
-- index covers the same key on the finished side.
--
-- Tiny in practice: only the finished CREATE_RUN rows are indexed,
-- which is far fewer than the active partial index covers in a
-- healthy queue.
--
-- IF NOT EXISTS keeps the migration a no-op in production where the
-- index was created manually with CONCURRENTLY ahead of the deploy.

CREATE INDEX IF NOT EXISTS idx_jobs_create_run_finished_repo
ON jobs ((payload ->> 'repo_id'))
WHERE type = 'CREATE_RUN' AND finished_at IS NOT NULL;
