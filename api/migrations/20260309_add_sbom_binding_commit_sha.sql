-- Add commit_sha to sbom_bindings for direct hash-based lookup.
-- This denormalizes the commit hash from repo_commits so that SBOM→commit
-- lookups are keyed on the hash itself, not on RepoCommit UUIDs that can be
-- deleted when repos are removed.

ALTER TABLE sbom_bindings ADD COLUMN IF NOT EXISTS commit_sha VARCHAR(64);

CREATE INDEX IF NOT EXISTS idx_sbom_binding_commit_sha ON sbom_bindings (commit_sha)
    WHERE commit_sha IS NOT NULL AND commit_sha != '';

-- Backfill existing rows by joining through repo_commits.
UPDATE sbom_bindings sb
SET commit_sha = rc.commit_sha
FROM repo_commits rc
WHERE sb.asset_type = 'REPO_COMMIT'
  AND sb.asset_ref_id = rc.id
  AND (sb.commit_sha IS NULL OR sb.commit_sha = '');
