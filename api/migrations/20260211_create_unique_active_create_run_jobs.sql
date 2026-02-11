-- Prevent duplicate active CREATE_RUN jobs for the same repo+commit key.
-- This is scoped to active queued/retry states to preserve historical rows.
-- Key derivation:
--   repo_id: payload->>'repo_id'
--   commit : commit_hash (if set) else payload->>'commit_sha'

WITH ranked AS (
  SELECT
    id,
    ROW_NUMBER() OVER (
      PARTITION BY
        payload->>'repo_id',
        COALESCE(NULLIF(commit_hash, ''), NULLIF(payload->>'commit_sha', ''))
      ORDER BY created_at DESC, id DESC
    ) AS rn
  FROM jobs
  WHERE type = 'CREATE_RUN'
    AND status IN ('QUEUED', 'RETRY')
    AND payload->>'repo_id' IS NOT NULL
    AND payload->>'repo_id' <> ''
    AND COALESCE(NULLIF(commit_hash, ''), NULLIF(payload->>'commit_sha', '')) IS NOT NULL
)
DELETE FROM jobs j
USING ranked r
WHERE j.id = r.id
  AND r.rn > 1;

CREATE UNIQUE INDEX IF NOT EXISTS ux_jobs_create_run_active_repo_commit
ON jobs (
  (payload->>'repo_id'),
  (COALESCE(NULLIF(commit_hash, ''), NULLIF(payload->>'commit_sha', '')))
)
WHERE type = 'CREATE_RUN'
  AND status IN ('QUEUED', 'RETRY')
  AND payload->>'repo_id' IS NOT NULL
  AND payload->>'repo_id' <> ''
  AND COALESCE(NULLIF(commit_hash, ''), NULLIF(payload->>'commit_sha', '')) IS NOT NULL;
