# ADR-0003: Immutable SBOM artifacts with bindings

## Status
Accepted

## Context
SBOMs must support forks, uploads, and multiple sources while remaining auditable.

## Decision
SBOMs are immutable and deduplicated by content hash.
Bindings attach SBOMs to repos, commits, or images.

## Consequences
Positive:
- Fork-safe
- Audit-friendly
- No accidental mutation

Negative:
- Slightly more schema complexity

## Alternatives considered
- Mutable SBOM rows: rejected (audit risk)
