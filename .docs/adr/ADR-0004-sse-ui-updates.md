# ADR-0004: Server-Sent Events for UI updates

## Status
Accepted

## Context
Users require live feedback for jobs and findings.
Bidirectional communication is not required.

## Decision
Use Server-Sent Events backed by a durable outbox table.
Support replay via Last-Event-ID.

## Consequences
Positive:
- Simple implementation
- Works well with HTTP and ingress controllers

Negative:
- Server-to-client only

## Alternatives considered
- WebSockets: rejected (complexity)
- Polling only: rejected (poor UX)
