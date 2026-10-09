# AGENTS.md

## Repository mission

`cwl-telemetry` is the optional canonical owner of the shared, explicit
OpenTelemetry runtime, Collector routing template, normalized security-event
receiver, and SIEM delivery contract. Product repositories retain domain
events, authorization decisions, audit truth, credential lifecycle, and
deployment ownership.

This repository is pre-release. An open PR or passing predecessor check is
Proposed evidence only; consumers must use a disabled feature flag or contract
test double until a protected-main build has an immutable version and digest.

## Required workflow

1. Fetch the current PR head and default-branch head before changing anything.
2. Review every open PR thread and exact-head check. Preserve concurrent work;
   use ordinary descendant commits only—never force-push or destructively
   rebase.
3. Start behavioral changes with a failing test at the canonical writer.
4. Run the smallest relevant test first, then the complete locked gate:
   `uv sync --locked --group dev --no-install-project`,
   `uv sync --locked --group dev --no-build-isolation`, and
   `uv run --no-sync pytest -q`.
5. Build with `uv build --no-build-isolation` and verify the source
   distribution contains `collector/production.yaml`.
6. Update `CHANGELOG.md` and
   `docs/product-technical-gap-baseline.md` with exact revision and workflow
   evidence. Do not convert Proposed decisions to Accepted from documentation.
7. Keep the PR Draft until current-head Checks are terminal green and an
   independent reviewer approves it. Merge normally; publish only from the
   protected default branch.

A hosted job with no executed steps and no log blob is runner evidence, not a
product regression. Record its job identity and continue safe work; do not
change source merely to retrigger infrastructure.

## Ownership and dependency rules

- Public product code depends only on an immutable released package or HTTPS
  contract, never this branch, this repository's database, or copied source.
- `security_event_outbox` is private to the receiver/sender subsystem.
- The authenticated tenant is supplied by the receiver credential boundary,
  never trusted from the OTLP record alone.
- The Collector admits TLS-authenticated OTLP and separates operational from
  normalized security records.
- Only an exact event-ID acknowledgement marks delivery. Authenticated,
  event-specific HTTP 400/422 rejection may quarantine; ambiguous failures stay
  pending.
- Never log bearer tokens, raw security records, private keys, or request
  headers. Use synthetic credentials and events in tests.
- Keep the runtime inert on import. Network, provider, thread, and process
  creation require explicit bootstrap or CLI execution.

## Change discipline

Prefer the smallest causal change. Do not add a platform, control plane, shared
database, UI, or new provider abstraction without measured repeated demand and
an ADR. Preserve bounded inputs, finite vocabularies, explicit timeouts, TLS
1.2 minimum, private regular-file checks, exact acknowledgements, and durable
failure semantics.

Public modules, classes, functions, and methods require docstrings. Tests must
cover hostile boundaries and failure paths, including replay, conflicting
identity, mixed tenant, slow request, TLS failure, redirect, malformed
acknowledgement, restart, capacity exhaustion, and quarantine behavior.

## Evidence and handoff

`ARCHITECTURE.md` is the context and invariant authority.
`docs/security-operability.md` is the operator and incident authority.
`docs/product-technical-gap-baseline.md` is the live PRD/TRD/Gap status.
`CLAUDE.md` is a concise entry point and must not duplicate these contracts.
