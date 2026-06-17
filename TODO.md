# TODO — SCAM fleet observability (agent health view)

Consume the enriched SCAM heartbeat (see scam branch `feat/agent-healthz`)
and surface fleet health for 400+ agents: totals, memory/CPU usage,
version spread, and outlier ("bad agent") detection.

The agent now POSTs a health report to `/api/scam/heartbeat`, a superset
of the old `{"cluster_id": ...}` body:

```json
{
  "cluster_id": "<kube-system uid>", "version": "v0.3.0", "commit": "<sha>",
  "go_version": "go1.26.4", "uptime_seconds": 86400, "goroutines": 42,
  "heap_alloc_bytes": ..., "sys_bytes": ..., "rss_bytes": ...,
  "cpu_seconds_total": 1234.5, "num_gc": 88, "gc_pause_ms_total": 12.3
}
```

Session identity stays keyed on the kube-system `cluster_id` (the existing
`cluster_sessions` PK). ROR display fields (name/env/uid) come from the
existing `clusters` row join — the heartbeat does not duplicate them.

## 1. Schema
- [ ] Migration `api/migrations/20260617_cluster_sessions_health.sql`:
      `ALTER TABLE cluster_sessions ADD COLUMN agent_version text,
       agent_commit text, go_version text, uptime_seconds bigint,
       goroutines int, heap_alloc_bytes bigint, sys_bytes bigint,
       rss_bytes bigint, cpu_seconds_total double precision,
       prev_cpu_seconds double precision, prev_sample_at timestamptz,
       cpu_pct double precision, num_gc bigint, gc_pause_ms_total double precision;`
- [ ] Add the same fields to `ClusterSession` (`api/internal/scam/session.go:25`).
- [ ] No backfill needed — fields populate on the next heartbeat (≤5m).

## 2. Ingest
- [ ] `HeartbeatHandler` (`api/internal/scam/handler.go:621`): decode the
      richer body (keep ignoring unknown fields for forward-compat).
- [ ] On upsert, set the new columns. Compute `cpu_pct` from
      `(cpu_seconds_total - prev_cpu_seconds) / (now - prev_sample_at)`,
      then store the current values as `prev_*`. Guard the first sample
      and counter resets (restart → cpu_seconds_total drops; treat as null
      cpu_pct, not negative).
- [ ] Keep bumping `last_push_at` exactly as today (liveness unchanged).

## 3. API (ACL-filtered like existing cluster handlers; register near `router.go:470`)
- [ ] `GET /api/agents` — one row/cluster: name/env (join `clusters`),
      version, commit, uptime, rss/heap, cpu_pct, goroutines, health
      (`live`/`stale`/`dead` from `last_push_at` vs `liveWindowInterval()`),
      `flapping` (low uptime or recent `last_seen_event_id` reset).
- [ ] `GET /api/agents/fleet-summary` — KPIs: totals, live/stale/dead,
      distinct versions, avg/p95/max rss + cpu_pct (computed in SQL).
- [ ] Fold version/commit/uptime/mem/cpu into `GET /api/cluster/{id}` for
      the per-cluster panel.

## 4. Web UI  (scatter was dropped — using a status-grid "fleet map")
- [x] `FleetMap.svelte` (`web/src/lib/components/`) — dense status grid,
      one cell per agent. Recolor by version / environment / health; bad
      agents (stale/dead/flapping) always ringed; swimlanes by env or zone;
      hover tooltip; KPI strip + legend. Cell colors transition, so a
      rollout animates across the grid when `agents` updates.
- [x] Playground harness `web/src/routes/(app)/playground/fleet/+page.svelte`
      — ~420 mock agents + Simulate-rollout / Inject-incident / Reset to
      preview the live transition. **View at `/playground/fleet`.**
- [ ] Wire FleetMap to real data: `GET /api/agents` for the initial set.
- [ ] Live updates via the existing SSE stream (`/api/app/stream`,
      `events/stream.go` + the `EventSource` in `(app)/+layout.svelte`):
      add an `agent_health` event dispatched from `HeartbeatHandler` (debounced)
      and patch the agent into the bound `agents` array → FleetMap animates.
- [ ] Final home: `web/src/routes/(app)/admin/settings/fleet/+page.svelte`,
      registered as a tab **right of Database** in `monitoringTabs`
      (`admin/settings/+layout.svelte`). Mount FleetMap + a fleet table
      (existing virtual-scroll/faceted-filter) for drill-down. (Mock lives
      at `/playground/fleet` until the backend is wired.)
- [ ] Per-cluster "Agent" card on `cluster/[id]/+page.svelte`: version,
      commit link, uptime, mem, cpu, health badge.

## 5. Scale / correctness (400+)
- [ ] 400 heartbeats / 5m ≈ negligible write load; `last_push_at` indexed.
- [ ] Fleet endpoint = current-state only (~400 rows) → fine to send whole.
- [ ] Outlier thresholds client-side off `fleet-summary` p95 (no server cost).

## 6. "Bad agent" signals (all derivable from the above)
leaking (rss/heap ≫ peers per object count) · busy (high cpu_pct) ·
flapping (low uptime / event-id resets) · laggard (old version) ·
silent (stale/dead).

## Phase 2 (deferred) — trends over time
- [ ] `cluster_agent_history` daily snapshot table + job; reuse
      `MultiLineChart` for version adoption / mem & cpu trends. Only once
      we're cutting regular releases and want rollout/laggard tracking.

## Datacenter / zone sizing (answers "how big is each DC?")
- [ ] NOT captured today: SPAM stores no zone/region/datacenter, and SCAM
      doesn't watch Nodes. Add to the SCAM health heartbeat: `node_count`
      and distinct `zones` (+ `region`/`provider`) read from node labels
      (`topology.kubernetes.io/zone`, `.../region`). Needs `nodes` list RBAC.
- [ ] Store on `cluster_sessions`; then FleetMap `group=zone` swimlane
      sizes show each datacenter's footprint, and KPIs can sum node_count
      per zone. The map already supports zone-grouping (mocked for now).

## Optional follow-ups on the agent (SCAM)
- [ ] Add `watched_objects` + `records_emitted_total` + `push_failures_total`
      to the heartbeat (needs counters in the push path) — better outlier
      axes and "struggling to push" detection.
- [ ] (Decided against for now) ROR metadata on the heartbeat — redundant
      with the `clusters` join and risks staleness.
