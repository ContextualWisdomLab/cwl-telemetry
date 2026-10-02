# Product and Technical Gap Baseline

Status: Proposed

Implementation evidence: hosted implementation checks are GREEN on PR #1 predecessor head `782445aadd6bb2ef3efe7bd688785d1fdb0588f5`; the PR records the latest exact head and its checks

Last reviewed implementation head: `782445aadd6bb2ef3efe7bd688785d1fdb0588f5` (`Telemetry contract` 36880180730, `Security Scan` 36880180408, `SAST Semgrep` 36880180583, and `CodeQL PR` 36880180318 all succeeded)

Release state: no immutable release; consumers must not adopt this branch

This baseline records what `cwl-telemetry` owns, what the current evidence
proves, and what still blocks a production release. Open PR evidence is
provisional. A passing check applies only to the exact head it evaluated.

## PRD: product goal and acceptance boundary

`cwl-telemetry` is the optional canonical owner of explicit OpenTelemetry SDK
bootstrap, bounded telemetry fields, and the Collector routing contract shared
by ContextualWisdomLab products. Products retain their domain truth,
authorization, authoritative audit outbox, credential rotation, and deployment
decisions.

A release candidate is acceptable only when:

1. importing the package creates no provider, thread, or network traffic;
2. product code explicitly bootstraps a bounded trace, metric, and log runtime;
3. authenticated OTLP separates operational and normalized security records;
4. security records remain durable and idempotent until an exact SIEM
   acknowledgement;
5. the exact protected-main revision passes contract, SAST, dependency, and
   CodeQL gates plus independent review;
6. immutable artifacts, hashes, schema evidence, and a consumer parity test are
   published before any consumer enables the integration.

## TRD: current evidence

| Requirement | Exact evidence | Status |
| --- | --- | --- |
| Explicit, inert bootstrap | hostile ambient OTel subprocess tests; explicit sampler and span limits; fail-closed SDK-disable admission | Hosted implementation evidence GREEN on `782445a...` / 36880180730 |
| Finite field and security-event vocabulary | `TelemetryConfig`, `TelemetryEvent`, `validate_event` | Implemented in Proposed PR |
| Authenticated TLS OTLP ingress and route separation | `collector/production.yaml`; pinned real-Collector tests | Implemented; deployment unverified |
| Tenant-bound normalized security projection | `decode_security_export`; hostile-record tests | Implemented in Proposed PR |
| Durable idempotency and exact acknowledgement | `security_event_outbox`; `deliver_pending`; failure-injection tests | Implemented in Proposed PR |
| Security-route integrity | exact built-in string fields; reserved security names require security kind/purpose/IDs; one immutable attribute snapshot is admitted and exported | Hosted implementation evidence GREEN on `782445a...` / 36880180730 |
| Poison-event isolation without false delivery | exact-ID and exact-Boolean JSON `400`/`422` rejection contract; pending+quarantine shared capacity; later-row delivery regression | Hosted implementation evidence GREEN on `782445a...` / 36880180730 |
| W3C trace correlation | mixed-case `traceparent` regression; duplicate case variants fail closed; baggage and TraceState are discarded | Hosted implementation evidence GREEN on `782445a...` / 36880180730 |
| Bounded OTLP record and batch size | 128-character event-name admission; inherited TraceState removal; real pinned-encoder burst test for 16-record log/trace batches | Hosted implementation evidence GREEN on `782445a...` / 36880180730 |
| Wire-safe counter totals | signed-int64 increment and canonical label-series cumulative admission with repeated-handle and concurrency tests against the pinned metric encoder | Hosted implementation evidence GREEN on `782445a...` / 36880180730 |
| TLS 1.2 minimum on synthetic HTTPS peers | Implementation commit `9da68ea...`; security decoder tests; CodeQL PR run 36880180318 | Hosted implementation and CodeQL evidence GREEN on `782445a...` |
| Package completeness | Telemetry contract run 36880180730 on `782445a...` ran the locked build, produced wheel and sdist, and verified packaged `collector/production.yaml` | Hosted implementation evidence GREEN; immutable release still absent |
| Release and consumer adoption | no published release; Naruon migration remains external | Blocked |

The runtime is Python because the supported OpenTelemetry SDK/exporter surface
is the interoperability boundary. It contains no mathematical or data-science
hot path. Reconsider a Rust native service only after profiling proves Python
CPU, concurrency, or isolation is the limiting cause.

## Context Map

```mermaid
flowchart TD
    Product[Product bounded context] -->|explicit SDK port| Runtime[cwl-telemetry runtime]
    Runtime -->|authenticated OTLP| Collector[OpenTelemetry Collector]
    Collector -->|operational signals| Backend[Telemetry backend]
    Collector -->|security schema v1| Consumer[Security consumer]
    Consumer -->|durable normalized row| Outbox[(SQLite outbox)]
    Outbox -->|pending rows| Sender[Operator-scheduled SIEM sender]
    Sender -->|HTTPS JSON and Idempotency-Key| SIEM[Approved SIEM gateway]
    SIEM -->|exact-ID acknowledgement| Sender
    Sender -->|mark delivered| Outbox
```

The runtime and Collector are an Anti-Corruption Layer between product-owned
Ubiquitous Language and vendor telemetry protocols. Product domain events never
become authoritative merely because they traverse this context.

## UML: security delivery sequence

```mermaid
sequenceDiagram
    participant P as Product
    participant C as Collector
    participant R as Security consumer
    participant O as Durable outbox
    participant D as SIEM sender
    participant S as SIEM gateway
    P->>C: Authenticated OTLP security event
    C->>R: Schema-v1 protobuf
    R->>O: BEGIN IMMEDIATE + idempotent insert
    R-->>C: Accepted after commit
    D->>O: Read pending row
    D->>S: HTTPS JSON + Idempotency-Key
    S-->>D: Exact event-ID acknowledgement
    D->>O: Mark delivered
```

Failure invariant: TLS, redirect, retryable or configuration HTTP failures,
malformed acknowledgement, process restart, or duplicate delivery cannot mark a
pending row delivered. Only an authenticated `400`/`422` JSON response bound to
the exact event ID moves the row to retained quarantine state `2`; generic
errors remain pending. Pending and quarantine rows share one capacity bound. A
reused event ID with different content is rejected.

## ERD: owned persistence

```mermaid
erDiagram
    SECURITY_EVENT_OUTBOX {
        text event_id PK
        text record_json
        integer time_unix_nano
        integer delivered
    }
```

Delivery state `0` is pending, `1` is acknowledged, and `2` is quarantined
after an authenticated event-specific permanent rejection. Quarantine is not
delivery and is retained for operator investigation.

This is a single normalized aggregate boundary: one immutable event payload and
its delivery state. The database is private to the security-consumer subsystem
and is shared only by its receiver and operator-scheduled sender processes;
other contexts use the released HTTPS contract and never query this table.

## Buyer-visible gaps and actions

| Priority | Gap | Action and completion evidence | Status |
| --- | --- | --- | --- |
| P0 | CodeQL rejected a prior head for implicit legacy-TLS flows | Require TLS 1.2 explicitly and obtain a successful CodeQL run on the successor exact head | Repaired; CodeQL PR 36880180318 GREEN on `782445a...` |
| P0 | Valid SDK bursts and inherited TraceState exceeded the Collector's 65,536-byte ingress limit | Bound trace/log exports to 16 records, preserve only parent trace identity/flags, and encode worst-case admitted batches with pinned OTel in the regression suite | Implementation GREEN on `782445a...` / 36880180730; independent approval and release remain |
| P0 | Operational event names and cumulative metric-series totals could exceed OTLP wire bounds | Reject event names above 128 characters and each canonical label-series total above signed-int64 before calling the SDK; synchronize repeated handles | Implementation GREEN on `782445a...` / 36880180730; independent approval and release remain |
| P0 | A generic or non-Boolean `400`/`422` rejection could falsely quarantine an event, while quarantine rows bypassed capacity | Require exact-ID and exact-Boolean rejection JSON, retain ambiguous failures as pending, and count pending+quarantine rows against one capacity | Hosted implementation evidence GREEN on `782445a...` / 36880180730 |
| P0 | Reserved security names could be downgraded to operational through ordinary or subclassed strings, and repeated mutable `Mapping` reads could remove required IDs after admission | Require exact built-in string fields, enforce the inverse name/kind invariant, and export the single validated attribute snapshot | Hosted implementation evidence GREEN on `782445a...` / 36880180730 |
| P0 | Ambient OTel sampler, span-limit, or SDK-disable variables could silently drop or truncate explicitly admitted telemetry | Own sampler and span limits in bootstrap; reject ambient global disable | Hosted implementation evidence GREEN on `782445a...` / 36880180730 |
| P1 | Mixed-case HTTP `traceparent` fields lost valid parent identity, while a value-dependent duplicate sentinel was order-sensitive | Match the field name case-insensitively while rejecting duplicate case variants independently of value | Hosted implementation evidence GREEN on `782445a...` / 36880180730 |
| P0 | No independent current-head approval | Complete review after all exact-head checks; repair every actionable finding | Open |
| P0 | No immutable release or consumer pin | Merge normally, build from protected main, publish hashes and contract evidence, then bump the consumer to the released artifact | Blocked by PR |
| P0 | Live backend, SIEM, credential rotation, retention, and persistent-volume recovery are unverified | Run an operator-owned staging exercise with redacted evidence and rollback | Open |
| P1 | Receiver admission latency/capacity lacks a reproducible SLO result | On stated hardware, measure 100 RPS at concurrency 16 with a 1 KiB/64 KiB payload mix and a 100,000-row backlog; require receiver p95 at or below 20 ms and report every rejection or timeout | Open |
| P1 | The single-threaded receiver lets idle unauthenticated peers serialize valid requests | Add a bounded worker/concurrency design or an authenticated front proxy, then prove valid-request latency under multiple slow clients | Open |
| P1 | Existing quarantine is not listed on later sender runs, so operator attention is not durable | Add a bounded quarantine list/count contract and runbook without treating quarantine as delivery | Open |
| P1 | Receiver token/private-key file type, ownership, and mode are not validated | Define supported secret-mount modes; reject symlinks and unsafe group/other access with executable tests | Open |
| P1 | Collector output URL variables can select plaintext HTTP despite the documented HTTPS boundary | Add a startup/preflight contract that rejects non-HTTPS operational and security destinations | Open |
| P1 | Sender overhead and external SIEM latency are conflated | Measure sender overhead against a loopback acknowledgement gateway with p95 at or below 20 ms, then report a separate end-to-end distribution including external gateway latency and outage retries | Open |
| P1 | Metrics payload size can still grow with admitted series cardinality | Profile the pinned SDK with the maximum declared metric vocabulary and realistic label combinations; add a cross-instrument series budget only if the encoded request can exceed 65,536 bytes | Open |
| P1 | Pending-row lookup has no measured large-outbox query plan | Measure realistic backlog sizes; add an index or partition only if the profile proves need | Open |
| P1 | Repository continuation guides are incomplete | Add `AGENTS.md`, `CLAUDE.md`, `ARCHITECTURE.md`, and security/operability runbooks; complete the existing CHANGELOG without duplicating domain contracts | Open |
| P1 | Package rights and release provenance are incomplete | Decide approved license terms, add PEP 621 ownership/project metadata, test the built wheel in isolation, generate SBOM/attestation, and protect immutable release tags | Open |
| P2 | UI, Figma, Storybook, and locale evidence do not exist | Keep out of scope: this repository owns a headless runtime and Collector contract; record a new ADR before adding an operator UI | Not applicable by current boundary |

## Decision and continuation rule

The selected boundary is a small released library plus deployable Collector and
security-consumer contracts. Another context must not query the outbox because
that couples it to the subsystem's private schema. Copying source or consuming
a temporary branch bypasses release evidence, while adding another writer risks
outbox integrity. Until an immutable release exists, consumers use a disabled
feature flag or a contract test double.

On every successor head, update the implementation identity and the gap table
from the actual PR, workflow logs, release artifacts, and deployment
experiments. A document cannot embed its own final commit SHA, so its immutable
workflow evidence belongs in the PR or check run. Never convert Proposed work
to Accepted from documentation alone.
