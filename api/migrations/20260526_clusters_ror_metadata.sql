-- 20260526_clusters_ror_metadata.sql
--
-- Promote ROR identity from "value of the cluster_id column" to "a
-- supplementary binding next to a stable kube-system UID primary key".
--
-- Why: SCAM previously emitted ROR's slug (e.g. t-tek-003-n2ua) as the
-- top-level cluster_id on every record. That entangled the SPAM join
-- key with ROR's identity domain — slugs can be re-pointed, renamed, or
-- absent on non-ROR clusters — making cluster_id unstable as a primary
-- key. SCAM now emits the kube-system Namespace UID as cluster_id (the
-- Kubernetes-canonical cluster fingerprint, k8s.cluster.uid in OTel),
-- and carries the ROR view in a nested `ror_metadata` object instead.
--
-- This migration promotes the three ROR fields out of the JSONB
-- pass-through and into typed columns on the `clusters` table so:
--   * the ACL filter can resolve ROR-sourced grants (slugs) back into
--     the kube-system UIDs we now key cluster_record on
--   * admins can find a cluster by its human-friendly ROR display name
--     without JSONB extraction across the record table
--
-- Cutover policy is "leave old rows orphaned" (see commit history) —
-- pre-cutover rows in `clusters` with `cluster_id = <ror-slug>` stay
-- in the table for forensic visibility but won't be joined by new
-- agent reports.

ALTER TABLE clusters
    ADD COLUMN IF NOT EXISTS ror_slug TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS ror_cluster_name TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS ror_env TEXT NOT NULL DEFAULT '';

-- Partial unique index: at most one row per non-empty ror_slug, but
-- the common "no ROR binding" case stays unconstrained. Lets the ACL
-- filter join through clusters.ror_slug with an index lookup instead
-- of a sequential scan.
CREATE UNIQUE INDEX IF NOT EXISTS ux_clusters_ror_slug
    ON clusters (ror_slug)
    WHERE ror_slug <> '';
