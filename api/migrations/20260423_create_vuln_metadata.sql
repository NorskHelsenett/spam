-- vuln_metadata caches enriched CVE/advisory detail fetched from
-- external feeds (OSV primary, EUVD secondary for CVE-prefixed IDs).
-- One row per vuln_id — upsert on every re-fetch so subsequent
-- enrichment sources can layer fields into the same row without
-- losing earlier data. raw_json keeps the merged source payloads so
-- future migrations can re-derive structured fields without re-
-- fetching every CVE from the upstream APIs.

CREATE TABLE IF NOT EXISTS vuln_metadata (
    vuln_id        text        PRIMARY KEY,
    title          text        NOT NULL DEFAULT '',
    description    text        NOT NULL DEFAULT '',
    severity       text        NOT NULL DEFAULT '',
    cvss_score     real        NOT NULL DEFAULT 0,
    cvss_vector    text        NOT NULL DEFAULT '',
    cwes           jsonb       NOT NULL DEFAULT '[]'::jsonb,
    -- references: [{url, type, label}]
    "references"   jsonb       NOT NULL DEFAULT '[]'::jsonb,
    -- aliases: cross-reference IDs (e.g. CVE-* <-> GHSA-* <-> BIT-*)
    aliases        jsonb       NOT NULL DEFAULT '[]'::jsonb,
    -- sources: which external feeds contributed (e.g. ["osv","euvd"])
    sources        jsonb       NOT NULL DEFAULT '[]'::jsonb,
    published_at   timestamptz,
    modified_at    timestamptz,
    raw_json       jsonb       NOT NULL DEFAULT '{}'::jsonb,
    fetched_at     timestamptz NOT NULL DEFAULT NOW()
);

-- Lookup by alias — so clicking "CVE-2024-1234" opens the same
-- metadata row as "GHSA-abcd-xyz-1234" when they're the same
-- advisory. GIN on aliases gives O(1) alias -> vuln_id resolution.
CREATE INDEX IF NOT EXISTS idx_vuln_metadata_aliases
    ON vuln_metadata USING GIN (aliases);

-- Reverse lookup for the enrichment worker: find rows whose fetch
-- is stale enough to warrant a re-pull from upstream (e.g. for
-- keeping CVSS up-to-date as scorings are revised). Nullable
-- modified_at is handled by NULLS FIRST so never-modified rows
-- sort to the front.
CREATE INDEX IF NOT EXISTS idx_vuln_metadata_fetched_at
    ON vuln_metadata (fetched_at);
