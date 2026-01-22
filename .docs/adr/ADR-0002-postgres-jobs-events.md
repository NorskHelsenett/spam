# ADR-0002: PostgreSQL for jobs and events

## Status
Accepted

## Context
The system requires background processing and event-driven UI updates.
Operational simplicity is prioritized.

## Decision
Use PostgreSQL tables as:
- Job queue (FOR UPDATE SKIP LOCKED)
- Durable outbox for events
Use LISTEN/NOTIFY only as a wake-up hint.

## Consequences
Positive:
- Durable, debuggable
- No extra infrastructure

Negative:
- Throughput limits at very large scale

## Alternatives considered
- NATS/Kafka: rejected due to ops overhead
- In-memory queues: rejected (not HA)
