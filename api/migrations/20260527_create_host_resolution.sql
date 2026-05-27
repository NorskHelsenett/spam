-- host_resolution: precomputed per-host classification for the
-- /api/clusters/hosts/summary endpoint. The previous implementation did
-- a synchronous DNS lookup per unique host inside the request handler,
-- which serialised into multi-second responses on fleets with even a
-- few hundred ingress hostnames. A background worker
-- (internal/hostresolve) now does that resolution off the request path
-- and upserts the result here; the summary endpoint joins host_exposure
-- to host_resolution and answers with pure SQL aggregates.
--
-- classification mirrors the buckets HostSummary already exposes:
--   internal     — DNS A record (or, when DNS fails, the LB-IP
--                  fallback) is RFC1918 / loopback / SPAM_HOST_INTERNAL_CIDRS
--   external     — DNS or LB-IP fallback resolves to a public address
--   unresolvable — DNS failed and there's no usable LB-IP fallback;
--                  reported as "pending" in the API response, but kept
--                  distinct on disk so we can re-resolve them on a
--                  shorter cadence than the happy path
--   pending      — never been resolved (worker hasn't reached the row yet)
--
-- resolved_at gates re-resolution. The worker re-resolves rows older
-- than its TTL (defaults to 6h) and any host present in host_exposure
-- that doesn't have a row here yet.
CREATE TABLE IF NOT EXISTS host_resolution (
    host           TEXT PRIMARY KEY,
    classification TEXT NOT NULL,
    ips            TEXT NOT NULL DEFAULT '',
    lb_ips         TEXT NOT NULL DEFAULT '',
    resolved_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Picking stale rows for the worker's re-resolve pass.
CREATE INDEX IF NOT EXISTS idx_host_resolution_resolved_at
    ON host_resolution (resolved_at);

-- Cheap filter for "show me the unresolvables" diagnostics; the summary
-- query itself uses the primary key join.
CREATE INDEX IF NOT EXISTS idx_host_resolution_classification
    ON host_resolution (classification);
