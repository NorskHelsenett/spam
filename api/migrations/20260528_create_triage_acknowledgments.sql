-- Asset-level acknowledgments for triage buckets. Append-only: every
-- snooze / suppress / accept-risk action writes a new row; revoke sets
-- revoked_at instead of deleting. The newest non-revoked row per
-- (asset_type, asset_id) is the live ack and gates whether the asset
-- appears in fix_now / this_week / watch.
--
-- action:
--   snooze                 — suppress until snooze_until; resurfaces automatically
--   suppress_until_change  — suppress while signals_fingerprint matches; the
--                            asset_risk refresh path revokes the row when the
--                            fingerprint drifts
--   accept_risk            — permanent suppression, only manual revoke clears it
CREATE TABLE IF NOT EXISTS triage_acknowledgments (
    id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    asset_type           TEXT NOT NULL CHECK (asset_type IN ('repo', 'image', 'cluster')),
    asset_id             TEXT NOT NULL,
    action               TEXT NOT NULL CHECK (action IN ('snooze', 'suppress_until_change', 'accept_risk')),
    reason_text          TEXT NOT NULL DEFAULT '',
    snooze_until         TIMESTAMPTZ,
    signals_fingerprint  TEXT,
    created_by           TEXT NOT NULL,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at           TIMESTAMPTZ,
    revoked_by           TEXT,
    revoked_reason       TEXT
);

-- Fast lookup of the live ack per asset. The "live" predicate is
-- revoked_at IS NULL AND (snooze_until IS NULL OR snooze_until > now()) —
-- we use a partial index so the common-case query is index-only.
CREATE INDEX IF NOT EXISTS idx_triage_ack_asset_active
    ON triage_acknowledgments (asset_type, asset_id)
    WHERE revoked_at IS NULL;

-- For the audit history panel: every ack on an asset, newest first.
CREATE INDEX IF NOT EXISTS idx_triage_ack_asset_history
    ON triage_acknowledgments (asset_type, asset_id, created_at DESC);

-- Per-CVE extensions to component_vex. Today VEX is purl+vuln keyed and
-- has no audit fields beyond created_at; this adds:
--   created_by      — the user who recorded the VEX
--   snooze_until    — same snooze semantics as the bucket ack
--   reason_text     — free-text justification beyond the CycloneDX code
--   asset_scope     — 'image:<digest>' | 'cluster:<id>' | NULL (global, purl-wide).
--                     Lets ops accept-risk a CVE on one image without
--                     silencing it everywhere the purl appears.
--   revoked_at      — append-only history of changes; new rows allowed
--                     once the active row is revoked.
ALTER TABLE component_vex
    ADD COLUMN IF NOT EXISTS created_by   TEXT,
    ADD COLUMN IF NOT EXISTS snooze_until TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS reason_text  TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS asset_scope  TEXT,
    ADD COLUMN IF NOT EXISTS revoked_at   TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS revoked_by   TEXT;

-- The legacy uniqueness on (purl, vuln_id) is too tight now that
-- asset_scope can vary. We need uniqueness on (purl, vuln_id,
-- asset_scope) where revoked_at IS NULL so an asset-scoped ack can
-- coexist with a global one and a revoked row can be superseded.
DROP INDEX IF EXISTS idx_component_vex_purl_vuln;

-- Column is p_url in this table (GORM auto-mapped from the PURL field
-- without an explicit column tag). component_vulnerabilities uses
-- "purl" because that model carries the explicit gorm:"column:purl"
-- override. Easy footgun — leaving the note in case a future model
-- edit changes either side.
CREATE UNIQUE INDEX IF NOT EXISTS idx_component_vex_purl_vuln_scope_active
    ON component_vex (p_url, vuln_id, COALESCE(asset_scope, ''))
    WHERE revoked_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_component_vex_history
    ON component_vex (p_url, vuln_id, created_at DESC);
