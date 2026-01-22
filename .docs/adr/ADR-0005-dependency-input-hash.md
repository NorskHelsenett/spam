# ADR-0005: Dependency-input hash for SBOM regeneration

## Status
Accepted

## Context
Code changes frequently, but dependency graphs do not.
Unnecessary SBOM regeneration is costly and noisy.

## Decision
Compute a dependency-input hash from dependency-defining files.
Regenerate SBOMs only when this hash changes.

## Consequences
Positive:
- Efficient scanning
- More accurate dependency risk modeling

Negative:
- Requires ecosystem-specific logic

## Alternatives considered
- Scan every commit: rejected (inefficient)
- Time-based scanning only: rejected (staleness)
