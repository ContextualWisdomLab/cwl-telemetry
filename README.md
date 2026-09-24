# CWL Telemetry

Shared runtime telemetry dependency for ContextualWisdomLab products. Importing
the package is inert. Applications call `bootstrap()` to opt in. This is an
unreleased draft for [CWL issue #1565](https://github.com/ContextualWisdomLab/.github/issues/1565).

```python
from pathlib import Path
from cwl_telemetry import TelemetryConfig, TelemetryEvent, bootstrap

runtime = bootstrap(TelemetryConfig(
    service="example", version="1.2.3", environment="prod",
    source_revision="<exact 40-lowercase-hex product commit>",
    receiver="https://collector.example:4318",
    token=Path("/run/secrets/otlp-token").read_text().strip(),
    ca_file="/run/secrets/collector-ca.crt",
    metric_names={"work_total"}, operation_codes={"work"},
))
with runtime.tracer.start_as_current_span("work", {"operation_code": "work"}):
    runtime.meter.counter("work_total").add(1, {"operation_code": "work"})
runtime.shutdown()
```

The example's source revision is a placeholder; deployment must inject the
actual product commit. A receiver requires HTTPS and a scoped token. The
product owns the token source and its rotation. Tracer attributes and metric
labels are admitted by finite vocabularies. Security events also require an
opaque tenant reference and stable 32-hex event ID. Authoritative audit and
domain events must use a separate durable product outbox.

## Signal route and ownership

| Step | Owner | Purpose | Retention |
| --- | --- | --- | --- |
| Product producer | Product team | Emit bounded operation signals and assign event IDs | Product audit retention is separate |
| Shared SDK | This package | Validate fields, classify records, bound in-process queues | Memory only; full queue drops oldest signals with a warning |
| Collector | Platform telemetry operator | Authenticate TLS/OTLP, batch, retry, persist outbound queues, route security records | Persistent queue requires a mounted volume and capacity monitoring |
| Telemetry backend | Backend operator | Operational logs, traces, metrics | Deployment policy must set limits before production |
| Normalized security consumer | Security operator | Validate event schema, tenant, time, replay; send approved events to SIEM | Durable outbox until acknowledged; SIEM retention requires owner policy |
| SIEM | Security operator | Investigate the finite security-event set | Deployment policy must set limits before production |

The [production Collector template](collector/production.yaml) has separate
authenticated HTTPS outputs for the operational backend and security consumer.
Only records classified as schema-v1 security events enter the latter route;
run one Collector and security consumer per tenant with distinct ingress and
consumer tokens. Start the included receiver with:

```sh
python -m cwl_telemetry.security_consumer \
  --certificate /run/secrets/receiver.crt \
  --private-key /run/secrets/receiver.key \
  --token-file /run/secrets/security-consumer-token \
  --tenant-ref tenant_1 \
  --outbox /var/lib/cwl-telemetry/security.sqlite \
  --listen 0.0.0.0
```

Mount a persistent
outbox directory and set the Collector's security output URL to this receiver's
HTTPS origin. The receiver creates a private SQLite outbox, admits only the
credential-bound tenant, and acknowledges an identical retry without storing a
second record. A reused event ID with different content is rejected. Events
may arrive up to seven days late to allow Collector recovery; clocks may be
five minutes ahead. Delivered event IDs remain reserved for that window.

The security operator sends `pending_security_events()` to its approved SIEM
destination and calls `mark_security_delivered()` only after a positive
downstream acknowledgement. No SIEM sender is bundled because no destination
or acknowledgement contract has been selected. The receiver cannot execute a
domain command or change authorization.

If the Collector is unavailable, product transactions continue and the SDK's
bounded queue may drop old operational signals. When the Collector's backend
or security consumer is unavailable, its persistent outbound queue retries
with backoff. A full outbound queue must surface as a receiver/export error;
operators must alert on drops and queue capacity. The security consumer's
SQLite outbox survives a restart. The operator's SIEM sender retries pending
rows after recovery. Product audit/outbox delivery is outside this
telemetry path.

## Verification and release boundary

Run `uv run pytest -q` and `uv build`. The tests use a pinned Collector image
for TLS, bearer, content-type, size, operational/security routing, and real
SDK trace/log/metric export. They test malformed schema, stale timestamps,
tenant mismatch, idempotent retry, conflicting replay, HTTPS admission, and a
persisted pending security event. No live backend or SIEM has been verified.
Operator-managed retention, persistent-volume deployment, an approved SIEM
sender, and a released consumer migration remain required before production.
