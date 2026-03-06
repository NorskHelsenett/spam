-- Normalize leading/trailing whitespace before enforcing non-empty identity fields.
UPDATE repos
SET
    org = BTRIM(org),
    slug = BTRIM(slug),
    provider_instance_id = BTRIM(provider_instance_id)
WHERE
    org <> BTRIM(org)
    OR slug <> BTRIM(slug)
    OR provider_instance_id <> BTRIM(provider_instance_id);

-- Fail fast if existing rows still violate the new constraints.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM repos
        WHERE org = '' OR slug = '' OR provider_instance_id = ''
    ) THEN
        RAISE EXCEPTION 'repos contains empty org, slug, or provider_instance_id values';
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
