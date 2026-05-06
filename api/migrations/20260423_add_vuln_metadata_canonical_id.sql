-- canonical_id collapses alias sets to a single preferred identifier
-- for counting and grouping. Preference order: CVE > GHSA > BIT > OSV
-- > self. An advisory stored under BIT-valkey-2025-49844 with CVE-
-- 2025-49844 in its aliases gets canonical_id = 'CVE-2025-49844', so
-- dashboards count it once and the list view groups BIT + CVE rows
-- together.
--
-- Nullable on insert so the app can populate it in-band via vulnmeta
-- helpers. Queries that need dedup fall back to COALESCE(canonical_id,
-- vuln_id) for rows without an enrichment row at all.

ALTER TABLE vuln_metadata ADD COLUMN IF NOT EXISTS canonical_id text;

-- Backfill for rows created before this column existed. Idempotent:
-- WHERE canonical_id IS NULL skips already-populated rows. Uses the
-- same preference order the app applies at Upsert time so historic
-- rows converge with freshly-enriched ones.
UPDATE vuln_metadata
SET canonical_id = COALESCE(
    (SELECT elem FROM jsonb_array_elements_text(aliases) elem
     WHERE elem LIKE 'CVE-%' ORDER BY elem LIMIT 1),
    (SELECT elem FROM jsonb_array_elements_text(aliases) elem
     WHERE elem LIKE 'GHSA-%' ORDER BY elem LIMIT 1),
    (SELECT elem FROM jsonb_array_elements_text(aliases) elem
     WHERE elem LIKE 'BIT-%' ORDER BY elem LIMIT 1),
    (SELECT elem FROM jsonb_array_elements_text(aliases) elem
     WHERE elem LIKE 'OSV-%' ORDER BY elem LIMIT 1),
    vuln_id
)
WHERE canonical_id IS NULL;

CREATE INDEX IF NOT EXISTS idx_vuln_metadata_canonical_id
    ON vuln_metadata (canonical_id);
