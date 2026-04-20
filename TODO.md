# TODO

Work items grouped by the core feature: **near real-time threat assessment
across the git repo → build → cluster runtime lifecycle**, for developers,
managers, and SOC operators.

Items near the top transform what SPAM *does*. Items below are polish on
existing surfaces.

---

## Bugs

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

- `sessionIdleGap = 2 min` — any silence longer than this on the next
  push rolls the session (stale state cleared).
- `sessionLiveWindow = 15 min` — cluster is "dark" after this much
  silence; UI shows nothing.

Agent-side work: spawn a goroutine alongside the event watchers that
ticks every 60s and POSTs `/api/scam/heartbeat` with the cluster_id.
~10 lines of code, no state.

### Fast-restart rollover

If the agent crashes + restarts in <2 min (fast liveness probe or
systemd restart), `touchClusterSession` won't detect the gap and the
prior session's stale rows linger. Proper fix: agent emits a
`session_id` (random UUID per process start) in each record; server
detects session_id change → roll over unconditionally. Until then,
stale state clears on the next genuine >2 min gap.

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

### Generalize HostChainDiagram to N columns

Diagram hard-codes Ingress → Service → Pod. Parameterize
`columns: {title, nodes}[]` so the same SVG primitives render:
- image-usage (Image → Cluster → Namespace → Pod)
- blast-radius (CVE → Repo → Image → Workload)
- service-mesh chains later

One component, many views. Unblocks items 2 and the image drawer
"where used" panel.

### Remove dead trivy handlers in uiapi

`uiapi.TrivyScanNextHandler` + `TrivyScanResultHandler` in
`uiapi/trivy_scanner.go` are unreferenced (runner package owns the
live route registrations). Delete the file.

### /api/trivy/* path rename

Cosmetic follow-up to the trivy-scanner → sbom-scanner rename. Endpoint
paths (`/api/trivy/next`, `/api/trivy/result/...`) still carry the old
name. Low priority — renaming is wire-level churn with no functional
gain, and the scanner binary no longer depends on the name.

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
