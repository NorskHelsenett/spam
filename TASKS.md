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
- [ ] Create `repo`
- [ ] Create `repo_commit`
- [ ] Create `sbom`
- [ ] Create `sbom_binding`
- [ ] Create `component`
- [ ] Create `component_version`
- [ ] Create `sbom_component`

Acceptance:
- SBOM deduplication enforced by `content_hash`
- `(repo_id, commit_sha)` uniqueness enforced
- Idempotent inserts possible

---

### 1.2 Identity and Access
- [ ] Create `group`
- [ ] Create `user_group`
- [ ] Create `access_scope`

Acceptance:
- Access decisions possible without user-specific hacks
- SOC/global access model supported

---

## Phase 2 – Job and Event Backbone

### 2.1 Job Queue
- [ ] Create `job` table
- [ ] Implement job lifecycle:
      QUEUED → RUNNING → SUCCEEDED / FAILED / RETRY
- [ ] Implement `FOR UPDATE SKIP LOCKED` worker logic

Acceptance:
- Jobs restart safely
- Multiple workers do not double-process jobs

---

### 2.2 Outbox Events
- [ ] Create `outbox_event` table
- [ ] Emit events for:
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
- [ ] Upload CycloneDX JSON
- [ ] Upload SPDX JSON
- [ ] Compute `content_hash`
- [ ] Store SBOM (bytea initially acceptable)
- [ ] Create sbom + binding
- [ ] Enqueue PARSE_SBOM job

Acceptance:
- Same SBOM uploaded twice is deduplicated
- Different repos can bind to same SBOM

---

### 3.2 SBOM Parsing Worker
- [ ] Parse components into normalized tables
- [ ] Handle missing or malformed fields safely
- [ ] Emit SBOM_PARSED event
- [ ] Mark job complete

Acceptance:
- Worker restart does not corrupt data
- Re-running job produces no duplicates

---

## Phase 4 – UI Basics

### 4.1 Repo Views
- [ ] Repo list (authorized only)
- [ ] Repo detail:
      - latest SBOM bindings
      - component list

### 4.2 Component Search
- [ ] Search by name / purl
- [ ] List impacted repos

Acceptance:
- Queries use normalized tables
- No JSON scanning at query time

---

## Phase 5 – Live Updates

### 5.1 SSE Endpoint
- [ ] Implement `/events`
- [ ] Support Last-Event-ID replay
- [ ] Heartbeat every 15–30 seconds

### 5.2 Postgres NOTIFY (Optional Optimization)
- [ ] NOTIFY on job/event insert
- [ ] LISTEN in API/worker to wake loops

Acceptance:
- SSE survives pod restarts
- No event loss after reconnect

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

## Exit Criteria (v1)

- SBOMs ingested and searchable
- Assets mapped to repos
- Live UI updates working
- Architecture stable enough to extend without refactors
