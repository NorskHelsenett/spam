# TODO

Work items grouped by the core feature: **near real-time threat assessment
across the git repo → build → cluster runtime lifecycle**, for developers,
managers, and SOC operators.

Items near the top transform what SPAM *does*. Items below are polish on
existing surfaces.

---

## Bugs

### Cluster overview: short security status

When opening a cluster (drawer or detail view), surface a compact summary strip showing: image count, vuln count, and SPAM Score.

### Remove animation on front page

The landing/front page should have no animation.

### SBOM vulnerability scanner doesn't log or show correct state

The SBOM vulnerability scanner doesn't log properly or show the correct state in the web UI.

### Triage: fetch real state for cluster/image/repo filters

In the triage view, selecting a cluster, image, or repo should fetch the actual items from the server (using a local cache where appropriate) so the user sees their real state instead of just the aggregated "total" counts.

### Search palette: image be more like repo in search

The image preview panel in search should be more like the repo visualization — richer visual layout with consistent styling and detail.

### Retry doesn't trigger an actual scanner pod

`POST /api/runs/{id}/retry` resets the job to `QUEUED` and clears locks
but doesn't call into the burst-trigger path. The job waits up to
~5 min for the reconciler's next tick, and that tick is further gated
by the 30-min burst cooldown — so a user clicking "Retry this failed
job" can wait 35+ minutes before anything happens.

Manual triggers should always fire faster than the scheduled 5-min
tick cadence. A click is a direct intent signal — the rate-limiter
(designed for ingest-driven bursts) has no business vetoing it.

Repro: `https://spam.torden.tech/app/runs/bfbd905f-23f1-46b5-8761-331e40be4945`.
After retry, job row shows `status=QUEUED attempts=0 run_at=now` but no
K8s Job spawns.

Fix:
- Expose a `TriggerNow(ctx)` (or `ForceBurst(ctx)`) on the reconciler
  that bypasses `minGapSinceCompletionSeconds`. Only callable from
  user-driven paths (`RunRetryHandler`, admin trigger handlers), not
  from the ingest or reconciler loops.
- For `IMAGE_SCAN` retries: call `TriggerNow` after the `UPDATE`. A
  scanner pod spawns within seconds, regardless of cooldown state.
- For `CREATE_RUN` retries: the worker's own job poller picks up
  QUEUED rows on its ~second-scale tick, so no extra trigger needed.

### Burst spawns two pods for one queued job

`imageScanner.parallelism` defaults to 2, so the image-scanner CronJob
template has `parallelism: 2 completions: 2`. Every burst (scheduled
tick or manual trigger) clones this template and fires two pods. With
one job in the queue:

1. Both pods start and race past the `/api/image-scans/pending` probe
   (both see `pending=1` before either has claimed).
2. Both download the grype DB (~60s, ~1 GB egress each).
3. Pod A wins the `SELECT FOR UPDATE SKIP LOCKED` on the single job.
4. Pod B sees an empty queue on its next loop, exits — but the DB
   download was already spent.

Thermally and cost-wise this is a real waste — roughly 2× the
bandwidth and 2× the CPU for no scanning throughput gain.

Fix options (pick one, most to least invasive):

- **Best: dynamic parallelism at burst time.** When the burst trigger
  spawns a Job, read the queue depth first and set `parallelism =
  min(queueDepth, defaultParallelism)`. `completions` follows. Keeps
  parallel throughput for bulk backfills, avoids waste for one-off
  retries.
- **Simpler: default `parallelism: 1`.** Scale out per-workload only
  when someone measures it's needed. Sequential processing of a
  typical homelab-sized fleet is fine — grype against a stored SBOM
  is fast once the DB is warm.
- **Cheapest but partial: move the pending probe into a busy-wait with
  jitter.** Pod B sleeps 10–30s after the probe before downloading the
  DB; if pod A claims the work in that window, B sees `pending=0` on
  re-probe and exits. Saves the DB download but not the pod spawn.

---

## Ship: near-real-time threat assessment

### 1. Alert emission — push, not pull

Today every signal is dashboard-only. A SOC analyst has to open the UI
to know a CVE landed in prod. This is the single biggest gap.

When reconciler pass 3 writes fresh findings, diff against the previous
scan and emit a structured event for:

- New `critical`/`high` CVE on a digest currently running
  (`cluster_record` with `pod_phase=Running`)
- `cosign` signature verification flipped from pass → fail on a previously-trusted image
- New secret finding in a repo whose images appear in the Workloads tab
- Scan run FAILED after retry exhaustion (operator attention needed)

Implementation path:
- Add `events.SecurityEvent` domain type + an outbox table
  (`security_events`). Re-use the existing `outbox_events` pattern.
- Implement a Slack-compatible webhook sink first (JSON body, configurable
  URL per provider_instance or globally). PagerDuty / email are thin
  adapters on top.
- Dedupe on `(event_type, subject_id, severity)` within a rolling window
  so a single CVE landing on 12 pods doesn't emit 12 alerts.

This is what turns SPAM from dashboard to monitor.

### 2. CVE blast-radius view

Given `CVE-2024-XXXX`, answer in one page:

- Which repos build images containing it (via `sbom_bindings` →
  component purls)
- Which image digests have it (from `image_vuln_findings`)
- Which clusters / namespaces / owners / pods run those digests
  (from `cluster_record`)
- Who the recent committers are on the linked repos
  (from `repo_caches.contributors_json`)

This is the flagship SOC workflow during an incident ("who is exposed?").

Implementation path:
- New endpoint `GET /api/vulnerabilities/{vuln_id}/impact` that returns
  the joined structure.
- New route `/app/vulnerabilities/[vuln_id]` rendering a page with four
  sections: summary, affected repos, affected images, affected workloads.
- Reuse `HostChainDiagram` in generalized 4-column mode
  (CVE → Repo → Image → Workload) if we get it refactored.

### 3. Ownership grouping for managers

Today every dashboard is cluster-wide. A manager viewing "my team's
posture" is a different product from "the whole estate" — same data,
filtered by owner.

Implementation path:
- Read `org.opencontainers.image.vendor` (or a configurable team label
  key via env) at OCI label extraction time. Store on
  `image_digests.team` (new column, AutoMigrate).
- Add a `team=?` filter to the main dashboard queries
  (`clusters/summary`, `images/detail`, vuln counts).
- Add a team selector to the app layout header. Persist choice in
  session.

### 4. Time-to-live + "first seen in prod" metric

We track `first_seen` / `last_seen` in `cluster_record` but don't
surface "this CVE has been in prod for 6 days" — which is exactly the
SLA number managers live on.

Implementation path:
- Derive per-(image_digest, vuln_id) "first detected" timestamp from
  `image_vuln_findings` history. Today the table doesn't keep history
  — findings are replaced each run. Either:
  - Keep history by never deleting old `scan_run_id` rows (already the
    case? verify); aggregate earliest `created_at` per
    (image_digest_id, vuln_id).
  - Or add a dedicated `vuln_first_seen` table updated on ingest.
- Show "X days in prod" chip next to each CVE on image detail and in
  the blast-radius view.

### 5. CISA KEV + policy layer

Elevate CVEs that CISA lists as known-exploited. Same data as VEX but
external-authoritative.

Implementation path:
- Daily pull of the CISA KEV JSON feed (small — ~1 MB). Cache in
  `kv_store`.
- Join at read time in `image_vuln_findings` queries; add a `kev=true`
  badge.
- Bump severity treatment: a "Medium" CVE on the KEV list should
  surface like a Critical.
- Future extension: a policy engine that can fail a run / block a
  deploy based on KEV presence + severity + age thresholds.

---

## Session tracking follow-ups

### SCAM agent must emit heartbeats

Server now expects `POST /api/scam/heartbeat` with body
`{"cluster_id": "..."}` every **60 s** when the cluster is quiet. Without
it, `last_push_at` ages out → cluster shows dark in the UI even though
the agent is alive and watching (example: a stable cluster with no pod
churn for 9 hours).

Server thresholds:

- `sessionLiveWindow = 1 h` (default; override via
  `SPAM_CLUSTER_LIVE_WINDOW`) — cluster is "dark" after this much
  silence; UI shows nothing.

Agent-side work: spawn a goroutine alongside the event watchers that
ticks every 60s and POSTs `/api/scam/heartbeat` with the cluster_id.
~10 lines of code, no state.

### Agent-side re-INITIAL on reconnect

Session rollover logic was removed from the server because the agent
doesn't reliably re-snapshot — a reconnect used to wipe all prior
resources until deltas trickled in. Liveness (last_push_at) alone is
the current visibility gate. To keep data canonical across very long
agent outages or re-deployments with changed state, the agent should
periodically (hourly?) resend INITIAL events for all currently-tracked
resources. Until then, stale resources from a decommissioned cluster
only fade out after `sessionLiveWindow` of total silence.

## Smaller follow-ups (from recent work)

### SBOM_SCANNER: grype → component_vulnerabilities

The OSV pipeline currently owns `component_vulnerabilities`.
Layering grype findings from repo-SBOM scans into the same table could
make the vulnerabilities page catch CVEs that OSV misses (distro
packages, binary catalogers). Needs a dedupe strategy on
`(purl, vuln_id)` and a `source` disambiguation — grype output already
carries enough data to populate most columns.

### scan_type marker on image_scan_runs

Today a full image scan and an SBOM-revuln both write
`image_scan_runs` rows with no way to tell them apart. Adding
`scan_type ENUM('full','sbom_revuln')` lets the scan-history UI on
`/app/images/[id]` distinguish "scanned image" from "rechecked SBOM",
which matters when the full scan was N days ago.

### Prune old SUCCEEDED jobs

The `jobs` table doubles as a permanent audit trail because nothing
removes SUCCEEDED rows after they're processed. Without pruning it
drifts back into multi-GB bloat over time and slows every claim query
in proportion, even with the new composite indexes.

Implementation path:
- New job type `PRUNE_OLD_JOBS`. Self-rescheduling like FETCH_KEV /
  FETCH_EPSS — daily cadence is fine.
- Handler deletes `WHERE status = 'SUCCEEDED' AND finished_at <
  NOW() - INTERVAL '30 days'`. Chunked DELETE in a loop with
  configurable batch size (default 10k) so it doesn't spike WAL.
- Optionally also prune `FAILED` rows older than N days, but those
  are more interesting to keep for forensics — make the threshold
  separate and larger (e.g. 90 days).
- Retention window configurable via env var
  (`JOBS_RETENTION_DAYS_SUCCEEDED`, default 30).
- Partial unique index `ux_jobs_prune_active` on `type='PRUNE_OLD_JOBS'`
  to keep the schedule idempotent across replicas.

Want this in place *before* the next swamp accumulates from any
source, not just VULN_META_FETCH.

### Tune postgres shared_buffers / work_mem

Stock postgres config is the default: `shared_buffers=128MB`,
`work_mem=4MB`, `effective_cache_size=4GB`. The container has 32 GB
RAM available so postgres is leaving most of it unused — visible as
~92% cache hit ratio (under the 99% healthy target for an OLTP DB)
and millions of temp files from sorts that overflow `work_mem`.

Implementation path:
- Extend `postgresql.primary.extraArgs` in the Helm chart with:
  ```yaml
  - "-c"
  - "shared_buffers=4GB"
  - "-c"
  - "work_mem=32MB"
  - "-c"
  - "maintenance_work_mem=1GB"
  - "-c"
  - "effective_cache_size=24GB"
  ```
- Bundles into the existing extraArgs (already used for the
  `pg_stat_statements` preload), so this is one rolling restart.
- `shared_buffers` requires postgres restart; the other three are
  reload-only — but bundling keeps one source of truth.

Expected effect: cache hit ratio → 98%+, MV-refresh sorts stop
spilling to disk, planner picks index scans more often. Revisit
the numbers a week after the next change rolls; if the slow-queries
panel is still spilling, push `shared_buffers` higher.

### Tombstone `vuln_metadata` rows for upstream-unknown CVEs

`processVulnMetaFetch` returns success-without-writing for two
branches: `not_found_upstream` (OSV/EUVD says the CVE doesn't exist)
and `upstream_error` (transient 403/429/5xx, decode mismatch,
timeout). Both leave the vuln_id permanently absent from
`vuln_metadata`. The new `EnqueueMissingVulnMeta` "already pending"
check + `ux_jobs_vuln_meta_active` unique index bound the damage,
but a vuln_id whose upstream lookup *will never succeed* keeps
getting re-enqueued on every scan — small steady churn forever.

Implementation path:
- Add `vuln_metadata.lookup_status` column: enum
  `('present', 'not_found_upstream', 'upstream_error')`. Default
  `present` so existing rows don't break.
- `processVulnMetaFetch` writes a tombstone row for the two
  non-success branches. The dedup check in
  `EnqueueMissingVulnMeta` already excludes anything in
  `vuln_metadata`, so tombstones naturally suppress re-enqueue.
- For `upstream_error` rows specifically: add a `next_retry_at`
  column and have `EnqueueMissingVulnMeta` skip rows whose
  `next_retry_at > NOW()`. Exponential backoff per id so a
  flapping upstream doesn't lock vuln_ids out forever.

This is belt-and-braces on top of the unique index, but it's what
turns "bounded steady-state churn" into "zero churn for known-dead
ids".

### Verify the totals on `/vulnerabilities` summary cards

Production summary shows 248,299 total vulns across 7,332 SBOMs
(8,137 critical / 65,542 high / 104,076 medium / 70,544 low+unknown).
These feel high enough that the methodology needs explicit
verification before anyone screenshots them into a slide deck.

`computeSummary` in `vulnmetrics/metrics.go` groups by
`(asset_type, asset_id, canonical_id)` and counts each distinct
triplet. That means:

- CVE-X on image A AND image B counts as 2 (one per asset).
- CVE-X reported by both grype and trivy on the same asset → 1
  (the GROUP BY dedupes within asset).
- CVE-X with a canonical_id matching GHSA-Y → 1 (canonical collapse).

So the total is "occurrences of unique advisories across assets",
not "distinct CVEs in the fleet". For a homelab-sized fleet with
many shared base images, that legitimately produces six-figure
totals — but the card label "TOTAL" doesn't tell the user that.

Action items:
- Pull the SQL apart and sanity-check the counts against a known
  digest's raw findings.
- Rename the card label (e.g. "asset findings" vs "distinct CVEs"),
  or add a second number for the unique-CVE count.
- Optionally surface a "double-counted across N assets" multiplier
  so the figure reads less alarming for execs.

### `/api/secrets/images` returns duplicates + stale images

`ImageSecretsTableHandler` (in `uiapi/secrets_dashboard_images.go`,
serving `/api/secrets/images` → the Secrets tab Images list) shows
the same image multiple times, and surfaces digests no longer running
in any cluster. Two related questions:

- Dedup: presumably grouping is by `scan_run_id` or `image_digest_id`
  but the JOIN to `image_scan_artifacts` (multiple categories per
  digest) is fanning rows out. Should dedupe to one row per digest.
- "Currently running" filter: today the result set spans every digest
  we've ever scanned, including digests that have rolled off all
  clusters. The Images tab on /clusters is liveness-gated against
  `cluster_sessions`; this endpoint should match that semantic, or
  explicitly offer an "include retired" toggle.

Cross-reference: the per-digest LATERAL artifact lookup at
`imagescan/linkresolver.go` was the same shape and was fixed with a
type-filter + new partial index. If this endpoint follows the same
pattern it may benefit from the same indexes already in place.

### `/api/runs/{id}` returning 504 on prod

Single-run detail endpoint times out on at least one run id
(`d195b6ed-d049-4204-bf29-9b72473faf21` in prod). Probably a query
fan-out that joins to image_vuln_findings or sbom_component_view
without an indexed predicate, or an N+1 inside the handler. The
60-second priv-router timeout fires before the response lands.

Investigation path:
- Look at `RunDetailHandler` (likely in `uiapi/runs.go`) — find every
  query it issues per request, and `EXPLAIN ANALYZE` the slowest
  against the offending run id.
- Check whether the handler pulls `run_secrets.findings` JSONB +
  derived dedupe (the timeline query in secrets_dashboard is heavy
  and might have a sibling in runs).
- If the slow path is a large jsonb_array_elements expansion, mirror
  the dependencies-list approach: cache by version watermark, or
  materialise into a sibling table updated on ingest.
- Also: surface the 504 properly on the frontend so the user sees
  "this run took too long to load" instead of a blank page.

### Reconcile image vuln counts between `/vulnerabilities` and `/clusters` Images

The image rows on `/clusters` Images come from `ImageDetailHandler`'s
`vuln_counts` CTE — per-digest counts off `image_vuln_findings` joined
to the latest finished `image_scan_runs` for that digest. The
`/vulnerabilities` page reads `view_unified_image_vulnerabilities`,
which de-dupes by `vuln_metadata.canonical_id` and groups across
assets.

Symptom: the "top" images on `/clusters` (sorted by weighted severity
sum) often don't surface near the top of `/vulnerabilities`, because
the latter ranks canonical-id rollups, not raw per-digest findings.

Investigation path:
- Pick a digest that ranks high on `/clusters` Images but isn't
  visible on `/vulnerabilities`. Diff its rows in
  `image_vuln_findings` vs `view_unified_image_vulnerabilities` —
  which CVEs disappear, which got rolled up.
- Check `vuln_metadata.canonical_id` for collapses that conflate
  distinct issues (CVE → GHSA pairs that should stay separate).
- Check whether the unified view excludes findings on a status flag
  (VEX `not_affected`, ignored, fixed-but-still-present).
- Decide a single source of truth: move `/clusters` to read from the
  unified view (consistent but slower per row), or document the two
  as different lenses and label them clearly in the UI.

### Generalize HostChainDiagram to N columns

Diagram hard-codes Ingress → Service → Pod. Parameterize
`columns: {title, nodes}[]` so the same SVG primitives render:
- image-usage (Image → Cluster → Namespace → Pod)
- blast-radius (CVE → Repo → Image → Workload)
- service-mesh chains later

One component, many views. Unblocks items 2 and the image drawer
"where used" panel.

---

## Reference: recently shipped on `feat/job-kubernetes-scanner`

For anyone coming to this file cold, what's already in:

- Image-scan pipeline end-to-end (lease, grype/syft/cosign/betterleaks
  runner, upload, artifact storage, worker HA).
- Workloads tab on `/app/providers/repo` with OCI-label onboarding for
  empty state.
- Image drawer in `/app/clusters` images tab (vuln severity, linked
  repo, committers, where running).
- Cluster drawer now shows recent non-running workloads muted.
- Nightly vuln recheck via grype against stored SBOMs (both
  `REPO_COMMIT` and `IMAGE_DIGEST`). Trivy dropped from the
  sbom-scanner image.
- SSRF hardening + favicon XSS fix + callcenter input validation.
- Per-run retry button; bulk reschedule now handles IMAGE_SCAN too.
- Partial-failure propagation so silent syft/grype crashes stop
  masquerading as successful scans.
