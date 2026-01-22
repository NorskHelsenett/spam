# ADR-0001: Modular monolith with stateless pods

## Status
Accepted

## Context
The system is early-stage with high domain complexity (SBOMs, assets, workflows).
Refactoring distributed systems early is costly and risky.

## Decision
Implement a single codebase (modular monolith) deployed as stateless API and Worker pods.
All state is persisted in PostgreSQL.

## Consequences
Positive:
- Easier schema evolution
- Strong transactional guarantees
- Simpler operations

Negative:
- Less independent scaling (acceptable at this stage)

## Alternatives considered
- Microservices: rejected due to premature complexity
