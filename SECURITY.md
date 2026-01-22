# SECURITY.md

## Purpose
This document defines the security posture, trust boundaries, and disclosure process
for this repository. The goal is to *practice what we enforce* in the SBOM platform.

---

## Supported Versions
Only the `main` branch and the latest tagged release are supported for security fixes.

---

## Reporting a Vulnerability

**Do not open public issues for security vulnerabilities.**

Instead:
- Email: security@your-org.example
- Or use your organization’s private disclosure channel

Please include:
- A clear description of the issue
- Steps to reproduce (if applicable)
- Impact assessment (what could be compromised)

We aim to respond within **5 business days**.

---

## Trust Boundaries

### User Boundary
- Users authenticate via OIDC.
- Authorization is enforced via group-based RBAC.
- UI is untrusted; all enforcement happens server-side.

### System Boundary
- API and Worker pods are stateless.
- PostgreSQL is the system of record.
- No secrets are stored in plaintext.

### External Integrations
- Git providers (GitHub/GitLab) accessed via scoped OAuth tokens.
- Tokens are encrypted at rest.
- Least-privilege scopes are required.

---

## Data Handling

### SBOM Data
- SBOM artifacts are immutable.
- Raw SBOM content is stored as-is for auditability.
- Parsed metadata is derived data.

### Secrets
- Secret scanning never stores raw secrets.
- Only fingerprints and locations are stored.

### Logs
- Logs must not contain secrets, tokens, or SBOM payloads.
- Structured logging is preferred.

---

## Security Controls

- OIDC authentication
- Group-based RBAC
- Idempotent background jobs
- Audit trail via outbox events
- Dependency deduplication via content hashing

---

## Hardening Guidelines

- Enforce HTTPS everywhere
- Use database migrations for all schema changes
- Prefer allowlists over denylists
- Fail closed on authorization errors

---

## Incident Response

In the event of a suspected compromise:
1. Rotate affected credentials immediately
2. Disable affected integrations
3. Preserve logs and database state
4. Notify security contacts

---

## Compliance Philosophy

This project aims to:
- Be auditable by design
- Favor explicit over implicit behavior
- Minimize implicit trust
