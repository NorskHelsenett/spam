# TASKS.md

## Purpose
This file defines the concrete implementation plan for the SBOM dashboard.
It is written to be executable by:
- a human engineer
- an AI agent

Tasks are ordered to minimize refactors and preserve architectural integrity.

---

## Phase 0 – Foundation (Done / Assumed)
- [x] Kubernetes deployment
- [x] PostgreSQL available
- [x] OIDC authentication working
- [x] Frontend scaffold deployed

---

## Phase 1 – Schema Spine (Highest Priority)

### 1.1 Core Tables
- [x] Create `repo`
- [x] Create `repo_commit`
- [x] Create `sbom`
- [x] Create `sbom_binding`
- [x] Create `component`
- [x] Create `component_version`
- [x] Create `sbom_component`

Acceptance:
- SBOM deduplication enforced by `content_hash`
- `(repo_id, commit_sha)` uniqueness enforced
- Idempotent inserts possible

---

### 1.2 Identity and Access
- [x] Create `group`
- [x] Create `user_group`
- [ ] Create `access_scope`
- [x] Require admin approval for new users after the first admin

Acceptance:
- Access decisions possible without user-specific hacks
- SOC/global access model supported

---

## Phase 2 – Job and Event Backbone

### 2.1 Job Queue
- [x] Create `job` table
- [x] Implement job lifecycle:
      QUEUED → RUNNING → SUCCEEDED / FAILED / RETRY
- [x] Implement `FOR UPDATE SKIP LOCKED` worker logic

Acceptance:
- Jobs restart safely
- Multiple workers do not double-process jobs

---

### 2.2 Outbox Events
- [x] Create `outbox_event` table
- [x] Emit events for:
      - JOB_CREATED
      - JOB_STATUS_CHANGED
      - SBOM_BOUND
      - SBOM_PARSED

Acceptance:
- All user-visible state changes emit events
- Events are append-only

---

## Phase 3 – Manual SBOM Upload (First Value)

### 3.1 Upload API
- [x] Upload CycloneDX JSON
- [x] Upload SPDX JSON
- [x] Compute `content_hash`
- [x] Store SBOM (bytea initially acceptable)
- [x] Create sbom + binding
- [x] Enqueue PARSE_SBOM job

Acceptance:
- Same SBOM uploaded twice is deduplicated
- Different repos can bind to same SBOM

---

### 3.2 SBOM Parsing Worker
- [x] Parse components into normalized tables
- [x] Handle missing or malformed fields safely
- [x] Emit SBOM_PARSED event
- [x] Mark job complete

Acceptance:
- Worker restart does not corrupt data
- Re-running job produces no duplicates

Note: Implemented in `jobs/processor.go`. Uses upsert patterns with
unique constraints to ensure idempotency.

---

## Phase 4 – UI Basics

### 4.1 Repo Views
- [ ] Repo list (authorized only)
- [ ] Repo detail:
      - latest SBOM bindings
      - component list

### 4.2 Component Search
- [x] Search by name / purl
- [x] List impacted repos
- [x] Filter by ecosystem
- [x] Component detail with versions
- [x] Show repos and images per component

### 4.3 SBOM Upload UI
- [x] Upload dialog with repo URL parsing
- [x] Form fields: org, slug, commit SHA, ref, provider, format
- [x] Auto-detect CycloneDX/SPDX format
- [x] Success/error feedback

Acceptance:
- Queries use normalized tables
- No JSON scanning at query time

---

## Phase 5 – Live Updates

### 5.1 SSE Endpoint
- [x] Implement `/api/app/stream`
- [ ] Support Last-Event-ID replay (required by ADR-0004)
- [x] Heartbeat every 20 seconds

Implementation note: Current SSE broadcasts live events via in-memory
pub/sub but does NOT support replay. To fulfill ADR-0004:
- Query `outbox_event` for events after Last-Event-ID on connect
- Include event ID in SSE `id:` field
- Consider adding `user_id` column to outbox for scoped replay

### 5.2 Postgres NOTIFY (Optional Optimization)
- [x] NOTIFY on job/event insert
- [x] LISTEN in API to wake SSE dispatch

Acceptance:
- SSE survives pod restarts
- No event loss after reconnect ← **Currently not met**

---

## Phase 6 – Provider Integration (Later)

### 6.1 GitHub
- [ ] OAuth integration
- [ ] Repo discovery
- [ ] Default branch tracking

### 6.2 GitLab
- [ ] OAuth integration
- [ ] Repo discovery

Acceptance:
- Providers abstracted behind interface
- Repo model unchanged

---

## Phase 7 – Automation

### 7.1 SBOM Generation
- [ ] Detect dependency-input changes
- [ ] Generate SBOM only when needed
- [ ] Bind generated SBOMs

### 7.2 Scheduling
- [ ] Nightly scan jobs
- [ ] Manual rescan trigger

---

## Phase 8 – Security Analysis

### 8.1 Vulnerability Evaluation
- [ ] Integrate vuln data source
- [ ] Create `finding` model
- [ ] Map findings to SBOMs

### 8.2 Workflow
- [ ] Acknowledge / suppress
- [ ] Expiry enforcement
- [ ] Audit trail

---

## Phase 9 – Posture and Secrets

### 9.1 Repo Practice Scans
- [ ] CODEOWNERS presence
- [ ] Lockfile checks
- [ ] Branch protection checks

### 9.2 Secrets Scanning
- [ ] Scan commit history
- [ ] Store fingerprints only
- [ ] Remediation workflow

---

## Guardrails

- Never mutate SBOM rows
- Never store secrets in plaintext
- Never bypass job system for background work
- Always emit outbox events for visible changes

---

## Technical Debt (from code review 2026-01)

### High Priority
- [ ] SSE Last-Event-ID replay not implemented (ADR-0004 gap)
- [ ] Potential race in `events/stream.go` dispatch (channel close during send)

### Medium Priority
- [ ] Remove duplicate log statements in `uiapi/sboms.go:115-116`
- [ ] Replace custom `itoa()` with `strconv.FormatUint`
- [ ] Make job retry backoff configurable (currently hardcoded linear)
- [ ] Remove unused `db` parameter from admin handlers

### Low Priority
- [ ] Align Svelte syntax to v5 conventions (`on:click` → `onclick`)
- [ ] Add client-side error logging in upload dialog

---

## Exit Criteria (v1)

- SBOMs ingested and searchable
- Assets mapped to repos
- Live UI updates working
- Architecture stable enough to extend without refactors
