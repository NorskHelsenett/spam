-- Versions-behind delta on dep_health, computed once per sweep
-- against the most-recent manifest_dependencies row for the
-- (ecosystem, package_name) pair. ADD COLUMN IF NOT EXISTS keeps
-- the migration idempotent under repeated boot.

ALTER TABLE dep_health
    ADD COLUMN IF NOT EXISTS versions_behind_major int NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS versions_behind_minor int NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS versions_behind_patch int NOT NULL DEFAULT 0;

CREATE INDEX IF NOT EXISTS idx_dep_health_major_behind
    ON dep_health (versions_behind_major) WHERE versions_behind_major > 0;
