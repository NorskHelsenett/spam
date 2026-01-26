# AGENT.md

## Purpose
This document defines how humans and AI agents should work in this repository.
It establishes guardrails to prevent architectural drift and unnecessary refactors.

The system prioritizes:
- Simplicity
- Durability
- Low operational overhead
- Incremental evolution

All contributors (human or AI) must align with this file.

---

## Core Principles

### 1. Monolith First
- The system is a **modular monolith**.
- One codebase, multiple runtime entrypoints (API, Worker).
- No microservices unless explicitly approved via ADR.

### 2. Stateless Runtime
- Pods must be stateless.
- All durable state lives in PostgreSQL.
- No in-memory queues as a source of truth.

### 3. PostgreSQL is the Backbone
- PostgreSQL is used for:
  - Primary data store
  - Job queue
  - Event outbox
- LISTEN/NOTIFY is allowed only as a wake-up hint.

### 4. Immutable Artifacts
- SBOMs are immutable.
- Never update an SBOM row.
- Metadata and bindings may change.

### 5. Event-Driven UX (Without a Broker)
- Use outbox events + SSE.
- No Kafka/NATS unless explicitly introduced via ADR.

---

## Required Modules

All code must fit into one of these logical modules:

- auth        : OIDC login, sessions, users, groups, RBAC
- assets      : repos, commits, clusters, workloads
- artifacts   : SBOM storage and bindings
- inventory   : SBOM parsing, components, licenses, ecosystems
- jobs        : job queue, workers, job types, processing
- events      : outbox, SSE streaming, NOTIFY/LISTEN
- uiapi       : HTTP handlers for frontend (uploads, admin, queries)
- server      : router, middleware, health checks
- config      : environment and runtime configuration
- db          : database connection and lifecycle

Cross-module coupling should be explicit.

---

## Development Rules

### Database
- All schema changes via migrations.
- Enforce idempotency with UNIQUE constraints.
- Prefer constraints over application logic.

### Jobs
- All background work must go through the job system.
- Job handlers must be idempotent.
- Jobs must be restart-safe.

### Events
- Any user-visible state change emits an outbox event.
- SSE must support replay via Last-Event-ID.
- NOTIFY/LISTEN is a wake-up hint only; outbox is the source of truth.
- Event replay should query outbox, not rely on in-memory state.

### UI
- UI must be thin.
- No business logic in the frontend.
- All state transitions happen in the backend.

---

## When in Doubt
- Check existing ADRs.
- Prefer simpler solutions.
- Avoid premature optimization.
