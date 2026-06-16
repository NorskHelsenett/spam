-- 20260616_clusters_ror_cluster_uid.sql
--
-- Add the ROR cluster UID as a first-class, resolvable identifier on the
-- `clusters` table.
--
-- Why: ROR keys ACL grants by the apikey identifier, which after ROR's
-- identifier migration is the cluster UUID (e.g.
-- 28fa3acb-6add-46aa-a9d2-c0127efdcf7a), NOT the slug. SCAM now emits
-- that value as `ror_metadata.cluster_uid`, distinct from the
-- human-readable slug it still emits as `ror_metadata.cluster_id`.
--
-- Until now the only ROR identifiers SPAM could resolve a grant against
-- were ror_slug and ror_cluster_name. A grant keyed by the UUID matched
-- neither, so the cluster fell out of the caller's ACL set and out of
-- /api/me/clusters resolution — it showed the bare UUID with
-- resolved=false, and (worse) the cluster ACL filter silently dropped
-- the cluster from its viewers.
--
-- Storing the UID in its own column lets both resolution sites
-- (clusterACLFilterCol, resolveMeClusters) match a UUID-keyed grant
-- while ror_slug keeps the readable slug for display/search.

ALTER TABLE clusters
    ADD COLUMN IF NOT EXISTS ror_cluster_uid TEXT NOT NULL DEFAULT '';

-- Partial unique index: at most one row per non-empty ror_cluster_uid,
-- mirroring ux_clusters_ror_slug. Lets the ACL filter resolve a
-- UUID-keyed grant with an index lookup, and enforces the one-row-per-uid
-- invariant the upsert's atomic handoff relies on.
CREATE UNIQUE INDEX IF NOT EXISTS ux_clusters_ror_cluster_uid
    ON clusters (ror_cluster_uid)
    WHERE ror_cluster_uid <> '';
