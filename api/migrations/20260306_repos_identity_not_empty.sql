-- Delete repos with invalid identity fields (empty/whitespace org, slug, or provider_instance_id),
-- including data that depends on those repos.
CREATE TEMP TABLE tmp_bad_repos ON COMMIT DROP AS
SELECT id
FROM repos
WHERE COALESCE(BTRIM(org), '') = ''
   OR COALESCE(BTRIM(slug), '') = ''
   OR COALESCE(BTRIM(provider_instance_id), '') = '';

CREATE TEMP TABLE tmp_bad_repo_commits ON COMMIT DROP AS
SELECT rc.id
FROM repo_commits rc
JOIN tmp_bad_repos r ON r.id = rc.repo_id;

-- repo_caches existed only on installs from the d371158→65632a7 era; the
-- table moved to kv_store afterwards, so guard so fresh installs don't fail.
DO $$
BEGIN
    IF to_regclass('public.repo_caches') IS NOT NULL THEN
        EXECUTE 'DELETE FROM repo_caches WHERE repo_id IN (SELECT id FROM tmp_bad_repos)';
    END IF;
END $$;

DELETE FROM manifest_dependencies
WHERE manifest_id IN (
    SELECT m.id
    FROM manifests m
    JOIN tmp_bad_repos r ON r.id = m.repo_id
);

DELETE FROM manifests
WHERE repo_id IN (SELECT id FROM tmp_bad_repos);

DELETE FROM run_secrets
WHERE repo_id IN (SELECT id FROM tmp_bad_repos);

DELETE FROM run_logs
WHERE run_id IN (
    SELECT j.id
    FROM jobs j
    JOIN tmp_bad_repos r ON r.id = (j.payload->>'repo_id')
);

DELETE FROM jobs
WHERE id IN (
    SELECT j.id
    FROM jobs j
    JOIN tmp_bad_repos r ON r.id = (j.payload->>'repo_id')
);

WITH deleted_bindings AS (
    DELETE FROM sbom_bindings
    WHERE asset_type = 'REPO_COMMIT'
      AND asset_ref_id IN (SELECT id FROM tmp_bad_repo_commits)
    RETURNING sbom_id
)
DELETE FROM sboms s
WHERE s.id IN (SELECT DISTINCT sbom_id FROM deleted_bindings)
  AND NOT EXISTS (SELECT 1 FROM sbom_bindings b WHERE b.sbom_id = s.id);

DELETE FROM repo_commits
WHERE id IN (SELECT id FROM tmp_bad_repo_commits);

DELETE FROM repos
WHERE id IN (SELECT id FROM tmp_bad_repos);

-- Normalize whitespace for remaining rows before adding constraints.
UPDATE repos
SET
    org = BTRIM(org),
    slug = BTRIM(slug),
    provider_instance_id = BTRIM(provider_instance_id)
WHERE
    org <> BTRIM(org)
    OR slug <> BTRIM(slug)
    OR provider_instance_id <> BTRIM(provider_instance_id);

DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM repos
        WHERE COALESCE(BTRIM(org), '') = ''
           OR COALESCE(BTRIM(slug), '') = ''
           OR COALESCE(BTRIM(provider_instance_id), '') = ''
    ) THEN
        RAISE EXCEPTION 'repos contains empty identity fields after cleanup';
    END IF;
END $$;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conrelid = 'repos'::regclass
          AND conname = 'ck_repos_org_not_empty'
    ) THEN
        ALTER TABLE repos
            ADD CONSTRAINT ck_repos_org_not_empty CHECK (BTRIM(org) <> '');
    END IF;
END $$;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conrelid = 'repos'::regclass
          AND conname = 'ck_repos_slug_not_empty'
    ) THEN
        ALTER TABLE repos
            ADD CONSTRAINT ck_repos_slug_not_empty CHECK (BTRIM(slug) <> '');
    END IF;
END $$;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conrelid = 'repos'::regclass
          AND conname = 'ck_repos_provider_instance_id_not_empty'
    ) THEN
        ALTER TABLE repos
            ADD CONSTRAINT ck_repos_provider_instance_id_not_empty CHECK (BTRIM(provider_instance_id) <> '');
    END IF;
END $$;
