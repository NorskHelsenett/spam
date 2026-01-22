# OWNERS.md

## Purpose
This file defines ownership and responsibility for this repository.
Clear ownership is required for security, reliability, and velocity.

---

## Repository Owners

The following roles exist:

### Maintainers
- Own the architecture and roadmap
- Approve ADRs
- Approve breaking changes

### Security Owners
- Own SECURITY.md
- Triage vulnerability reports
- Approve security-related changes

### Contributors
- May submit pull requests
- Must follow AGENT.md and ARCHITECTURE.md

---

## Code Ownership Model

Ownership is **group-based**, not individual-based.

Recommended groups:
- `platform-maintainers`
- `security-owners`
- `core-contributors`

Actual group mapping is managed via the identity provider.

---

## Review Requirements

- Architecture changes require at least one Maintainer review
- Security-sensitive changes require Security Owner review
- Schema changes require review by a Maintainer

---

## Escalation

If ownership is unclear:
1. Escalate to Maintainers
2. If unresolved, escalate to Security Owners

---

## Philosophy

Ownership is:
- Explicit
- Auditable
- Required

Unowned code is considered a risk.
