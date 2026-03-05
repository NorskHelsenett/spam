-- Delete repos with no usable identity (empty org/slug) that have no associated data.
DELETE FROM repos
WHERE (org = '' OR slug = '')
  AND id NOT IN (SELECT DISTINCT repo_id FROM repo_commits);

-- Normalize empty-string provider_instance_id to NULL before backfill.
UPDATE repos SET provider_instance_id = NULL WHERE provider_instance_id = '';

-- Aggressive backfill: assign any remaining NULL provider_instance_id rows
-- by picking the best-matching enabled provider instance (most specific owner_path wins).
UPDATE repos r SET provider_instance_id = (
    SELECT pi.id
    FROM provider_instances pi
    WHERE pi.type = r.provider
      AND pi.enabled = true
      AND (pi.owner_path = '' OR r.org = pi.owner_path OR r.org LIKE pi.owner_path || '/%')
    ORDER BY CASE WHEN pi.owner_path != '' THEN 0 ELSE 1 END, pi.created_at
    LIMIT 1
)
WHERE provider_instance_id IS NULL;

-- Enforce NOT NULL now that all rows are backfilled.
ALTER TABLE repos ALTER COLUMN provider_instance_id SET NOT NULL;

-- The partial index for manual (NULL) repos is no longer needed.
DROP INDEX IF EXISTS ux_repo_identity_manual;

-- Replace the partial unique index for provider repos with a full unique index.
DROP INDEX IF EXISTS ux_repo_identity_provider;
CREATE UNIQUE INDEX IF NOT EXISTS ux_repo_identity ON repos(provider_instance_id, org, slug);
