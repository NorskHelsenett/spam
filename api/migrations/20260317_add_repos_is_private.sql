-- Add is_private column to repos table.
-- Populated during provider sync from the provider API's is_private/visibility field.
ALTER TABLE repos ADD COLUMN IF NOT EXISTS is_private BOOLEAN NOT NULL DEFAULT false;

-- Backfill from cached provider data where available. repo_caches was a
-- transient table (d371158→65632a7); fresh installs never had it, so skip
-- when absent and let the next provider sync populate is_private.
DO $$
BEGIN
    IF to_regclass('public.repo_caches') IS NOT NULL THEN
        EXECUTE $sql$
            UPDATE repos r
            SET is_private = COALESCE((rc.details_json::jsonb->>'is_private')::boolean, false)
            FROM repo_caches rc
            WHERE rc.repo_id = r.id
              AND r.is_private = false
              AND rc.details_json IS NOT NULL
              AND rc.details_json != ''
        $sql$;
    END IF;
END $$;
