# CWL Telemetry

[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/ContextualWisdomLab/cwl-telemetry)

CWL Telemetry is the proposed shared runtime telemetry contract for
ContextualWisdomLab products. It owns explicit, validated OpenTelemetry SDK
bootstrap and the Collector-to-operational-backend or normalized-security-event
routing boundary.

Products remain the owners of domain truth, authoritative audit/outbox events,
authorization, and credential rotation. They may adopt this package only after
an immutable release and consumer parity tests are available; this repository's
current implementation is still under review.

See the [repository README](../README.md) for the API example, signal ownership
matrix, degraded-mode behavior, security receiver contract, and release gates.
