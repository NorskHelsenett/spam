# Architecture Guardrails: Dependency Inventory Scanning System

## Purpose

This document defines **non‑negotiable architectural rules** for the
dependency scanning system. Any generated code must follow these
guardrails.

These rules exist to prevent incorrect architectural assumptions when
using LLMs for code generation.

------------------------------------------------------------------------

# System Overview

The system scans dependency inventories using **Trivy** across many
repositories and artifacts.

The system supports: - Nightly scans - Ad hoc scans - Multiple
dependency inventory formats

The system must operate **without performing dependency builds or
restores**.

------------------------------------------------------------------------

# Core Architectural Model

The system uses a **Worker → Queue → Scanner Pod** architecture.

Components:

  Component            Responsibility
  -------------------- -------------------------------------
  Worker Service       Owns batch lifecycle and queue
  PostgreSQL           Stores queue and batch state
  Kubernetes CronJob   Starts nightly scan workers
  Kubernetes Jobs      Run ephemeral scanner pods
  Scanner Pods         Execute Trivy scans
  Object Storage       Stores inventory inputs and results

Scanner pods are **stateless and disposable**.

------------------------------------------------------------------------

# Absolute Constraints

## No dependency builds or restores

Scanner pods must **never run commands like:**

-   npm install
-   pip install
-   dotnet restore
-   mvn install
-   gradle build
-   cargo build

Dependency resolution must come **only from existing files**.

------------------------------------------------------------------------

## Trivy DB is downloaded once per pod

Scanner pods must:

1.  Start
2.  Download Trivy DB
3.  Reuse that DB for all scans

Example:

    trivy image --download-db-only --cache-dir /trivy-cache

All scans must use:

    --skip-db-update

------------------------------------------------------------------------

## Pods pull work (never pushed)

Work must always be retrieved by scanner pods via the worker API.

Pods repeatedly call:

    POST /api/v1/trivy/batches/{batchKey}/next

Pods must **not receive work via push mechanisms**.

------------------------------------------------------------------------

## Queue leasing must use PostgreSQL row locks

Queue leasing must use:

    SELECT ... FOR UPDATE SKIP LOCKED

This ensures safe parallel scanning.

External queue systems must **not** be introduced.

------------------------------------------------------------------------

# Dependency Inventory Source Priority

For each artifact, the worker must choose the best inventory source
using this rule:

    lockfile > sbom > manifest > none

Because existing SBOMs are **not build/export derived**, lockfiles may
be more accurate.

------------------------------------------------------------------------

# Source Definitions

## Lockfile (highest priority)

Resolved dependency files with pinned versions.

Examples:

-   package-lock.json
-   yarn.lock
-   pnpm-lock.yaml
-   poetry.lock
-   Cargo.lock
-   Gemfile.lock
-   composer.lock
-   packages.lock.json
-   gradle.lockfile

------------------------------------------------------------------------

## SBOM

Supported formats:

-   CycloneDX
-   SPDX

SBOMs are **medium confidence** because they were not produced from
resolved builds.

------------------------------------------------------------------------

## Manifest

Examples:

-   package.json
-   pom.xml
-   requirements.txt
-   build.gradle
-   go.mod
-   csproj

Manifests may not contain resolved dependency versions.

Confidence level: **low**.

------------------------------------------------------------------------

## None

No usable inventory exists.

Artifact is marked **unscannable**.

------------------------------------------------------------------------

# Queue Item Model

Each queue item represents a **dependency inventory scan job**.

Required metadata:

    inventory_source
    inventory_format
    inventory_confidence
    dependency_scope
    scan_strategy

Confidence levels:

    high
    medium
    low

------------------------------------------------------------------------

# Scan Strategies

Scanner pods must support only these strategies.

## scan_sbom

Run when input is SBOM.

    trivy sbom <file>

------------------------------------------------------------------------

## scan_filesystem_input

Used for lockfiles and manifests.

Procedure:

1.  Download file to temp directory
2.  Use original filename
3.  Run:

```{=html}
<!-- -->
```
    trivy fs <directory>

------------------------------------------------------------------------

## mark_unscannable

No scan is executed.

Queue item is marked terminal.

------------------------------------------------------------------------

# Dependency Scope

Supported scopes:

    runtime
    runtime_and_dev

Defaults:

  Scan Type   Scope
  ----------- --------------
  Nightly     runtime
  Ad hoc      configurable

When supported, dev dependencies may be included using Trivy flags.

------------------------------------------------------------------------

# Batch Lifecycle

Batch states:

    pending
    running
    completed
    failed

Queue item states:

    pending
    leased
    done
    failed

A batch is completed when:

-   no pending items remain
-   no active leases remain
-   all items are done or failed

------------------------------------------------------------------------

# Scanner Pod Lifecycle

Scanner pods must follow this sequence:

1.  Start
2.  Download Trivy DB
3.  Request work from worker
4.  Fetch inventory input
5.  Run Trivy scan
6.  Upload result
7.  Report completion
8.  Repeat until batch complete
9.  Exit

Pods must **terminate when worker returns `BATCH_COMPLETE`**.

------------------------------------------------------------------------

# Storage Requirements

Inputs may be retrieved from:

-   HTTP
-   S3-compatible object storage
-   internal artifact storage

Outputs must be stored as **Trivy JSON reports**.

------------------------------------------------------------------------

# Scaling Model

The system scales by increasing **parallel scanner pods**.

Concurrency safety relies on:

    PostgreSQL row locking
    FOR UPDATE SKIP LOCKED

No distributed locking system is required.

------------------------------------------------------------------------

# Non‑Goals

The following must **not be implemented**:

-   dependency builds
-   dependency restores
-   shared Trivy cache between pods
-   alternative scanners
-   queue systems other than PostgreSQL
-   dependency resolution outside existing files

------------------------------------------------------------------------

# Design Philosophy

The system scans **the best available dependency inventory without
executing builds**.

Accuracy is tracked using **inventory confidence metadata**.

This allows the system to operate across thousands of artifacts while
remaining deterministic and scalable.
