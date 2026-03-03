-- Backfill provider_instance_id on repos that can be matched to a provider instance.
-- Uses the same heuristic as the former LATERAL JOIN in repo_search.go.
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

-- Drop the old provider+org+slug unique index (was created by GORM auto-migrate).
DROP INDEX IF EXISTS ux_repo_identity;

-- Unique index for provider-linked repos (provider_instance_id NOT NULL).
CREATE UNIQUE INDEX IF NOT EXISTS ux_repo_identity_provider
    ON repos(provider_instance_id, org, slug)
    WHERE provider_instance_id IS NOT NULL;

-- Unique index for manually-created repos (no provider instance).
CREATE UNIQUE INDEX IF NOT EXISTS ux_repo_identity_manual
    ON repos(provider, org, slug)
    WHERE provider_instance_id IS NULL;

-- Index for efficient lookups by provider_instance_id.
CREATE INDEX IF NOT EXISTS idx_repos_provider_instance_id ON repos(provider_instance_id);
