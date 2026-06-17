-- host_resolution gains the public-DNS vantage from the hostresolve
-- worker's DoH lookup. The split-horizon problem: the worker's resolver
-- is the pod's (internal) resolver, which answers with the internal
-- zone record — so a host that ALSO has a public record was classified
-- internal, silently under-reporting exposure. classification is now
-- driven by the DoH answer when a host-specific one exists; these
-- columns record that answer so a verdict is explainable from the row:
--
--   public_ips — comma-joined A/AAAA answers from the public DoH
--                resolver; empty when public DNS has no record for the
--                host or the DoH endpoint was unreachable/disabled
--   wildcard   — the public answer matched the parent zone's wildcard
--                probe, so it proves zone-level exposure rather than a
--                host-specific public record; classification then
--                prefers the split-horizon answer
ALTER TABLE host_resolution ADD COLUMN IF NOT EXISTS public_ips TEXT NOT NULL DEFAULT '';
ALTER TABLE host_resolution ADD COLUMN IF NOT EXISTS wildcard BOOLEAN NOT NULL DEFAULT FALSE;
