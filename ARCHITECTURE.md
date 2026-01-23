# ARCHITECTURE.md

## Overview
This system is an SBOM dashboard designed to ingest, normalize, and analyze
software bills of materials across source repositories and runtime environments.

It is designed to:
- Scale incrementally
- Remain auditable
- Avoid unnecessary infrastructure

Dependency Analysis

  Component View ─────────────────────────────────► Stable, build now
                                                    (no schema changes)

  Provider Integration ──► Repo Sync ──► Commit Metadata ──► Rich Repo View
         │                     │              │
         │                     │              └─ message, author, timestamp
         │                     └─ auto-discover repos
         └─ store tokens, configure GitHub/GitLab

  Recommended Order

  Phase A: Component Search (do first - stable foundation)

  - Query interface over existing normalized tables
  - Won't change when providers are added
  - Immediate user value

  Phase B: Provider Foundation (do second - enables everything else)

  - Provider table with encrypted credentials
  - Repo sync jobs that fetch repo lists from GitHub/GitLab
  - Enrich repo_commit with message/author/timestamp
  - Provider management UI

  Phase C: Repo Views (do after providers)

  - Much richer with commit messages and auto-discovered repos
  - Filter by provider
  - Show sync status


---

## High-Level Architecture

```
Browser
  |
  |  HTTPS + SSE
  v
API (stateless)  <----> PostgreSQL (durable state)
  |
  | enqueue jobs
  v
Worker (stateless)
```

---

## Runtime Components

### API
Responsibilities:
- OIDC authentication
- RBAC enforcement
- Asset CRUD
- SBOM upload
- SSE event streaming

Deployed as multiple replicas.

### Worker
Responsibilities:
- Job processing
- SBOM parsing
- Provider sync (future)
- Scanning and analysis (future)

Deployed as multiple replicas.

### Scheduler
Implemented as Kubernetes CronJobs or a leader-elected loop.

---

## Data Model Philosophy

### Artifacts vs Bindings
- SBOMs are immutable artifacts.
- Bindings attach SBOMs to assets.
- Multiple assets may reference the same SBOM.

### Core Tables
- repo
- repo_commit
- sbom
- sbom_binding
- component
- component_version
- sbom_component
- job
- outbox_event

---

## Job System

- Implemented using PostgreSQL.
- Uses SELECT ... FOR UPDATE SKIP LOCKED.
- LISTEN/NOTIFY used only to wake workers.

Job lifecycle:
- QUEUED → RUNNING → SUCCEEDED / FAILED / RETRY

---

## Event System

- All events are written to outbox_event.
- SSE streams events to clients.
- Clients reconnect using Last-Event-ID.

---

## Ingestion Flow (Manual SBOM Upload)

1. User uploads SBOM
2. SBOM deduplicated by content hash
3. Binding created to repo/commit
4. Parse job enqueued
5. Worker normalizes components
6. Events emitted
7. UI updates via SSE

---

## Deployment Principles

- Stateless pods
- Multiple replicas
- Rolling updates
- Postgres HA preferred

---

## Future Extensions

- GitHub/GitLab integrations
- Automated SBOM generation
- Vulnerability evaluation
- Policy and notification system
- Secrets and posture scanning
