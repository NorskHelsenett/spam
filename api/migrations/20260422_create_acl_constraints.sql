-- ACL constraints and indexes.
--
-- The acl_grants and clusters tables are created by GORM AutoMigrate;
-- this file adds the bits AutoMigrate cannot express: CHECK constraints,
-- a deduplicating unique index over (subject, scope_type, pattern), and
-- the JSONB expression index that cluster scope filtering relies on.
--
-- Safe to re-apply: every statement is idempotent.

-- --------------------------------------------------------------------
-- acl_grants: shape constraints so a malformed row never reaches the
-- provider. The drop-before-add pattern means we can tighten or relax
-- the allowed value set in a later migration just by rewriting this
-- file; EnsureViews re-applies it when the hash changes.
-- --------------------------------------------------------------------

ALTER TABLE acl_grants
    DROP CONSTRAINT IF EXISTS acl_grants_subject_type_check;
ALTER TABLE acl_grants
    ADD CONSTRAINT acl_grants_subject_type_check
    CHECK (subject_type IN ('user', 'group'));

ALTER TABLE acl_grants
    DROP CONSTRAINT IF EXISTS acl_grants_scope_type_check;
ALTER TABLE acl_grants
    ADD CONSTRAINT acl_grants_scope_type_check
    CHECK (scope_type IN ('repo', 'cluster', 'image'));

ALTER TABLE acl_grants
    DROP CONSTRAINT IF EXISTS acl_grants_action_check;
ALTER TABLE acl_grants
    ADD CONSTRAINT acl_grants_action_check
    CHECK (action IN ('read'));

ALTER TABLE acl_grants
    DROP CONSTRAINT IF EXISTS acl_grants_source_check;
ALTER TABLE acl_grants
    ADD CONSTRAINT acl_grants_source_check
    CHECK (source IN ('migration', 'explicit', 'ingest_default'));

-- Deduplicate identical grants. md5(scope_pattern::text) keeps the
-- index size bounded for large patterns while still giving us a stable
-- identity check — JSON object key order from GORM's datatypes.JSON is
-- the Go map iteration order, which is unstable, so comparing raw JSON
-- text without normalization would miss duplicates. A small collision
-- risk is acceptable here because the row also constrains subject and
-- scope_type.
CREATE UNIQUE INDEX IF NOT EXISTS ux_acl_grant_identity
    ON acl_grants (subject_type, subject_id, scope_type, md5(scope_pattern::text), action);

-- --------------------------------------------------------------------
-- cluster_record: expression index on the hot cluster_id filter so the
-- JSONB extraction doesn't force a seq scan. This is a short-term fix
-- until cluster_id is promoted to a real column on cluster_record
-- (tracked in the plan's "Open follow-ups").
-- --------------------------------------------------------------------

CREATE INDEX IF NOT EXISTS idx_cluster_record_cluster_id
    ON cluster_record ((data->>'cluster_id'));
