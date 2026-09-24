"""Explicit, bounded telemetry Ports for CWL products.

Importing this module cannot create providers, threads, or network traffic.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from typing import Any, Mapping
from urllib.parse import urlsplit


_IDENTITY = re.compile(r"^[a-z][a-z0-9._-]{0,63}$")
_VERSION = re.compile(r"^[0-9A-Za-z][0-9A-Za-z._+-]{0,63}$")
_REVISION = re.compile(r"^[0-9a-f]{40}$")
_EVENT = re.compile(r"^[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+$")
_CODE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_REFERENCE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
_ATTRIBUTES = frozenset({
    "operation_code", "bounded_context", "tenant_ref", "workspace_ref",
    "principal_ref", "request_id", "trace_id", "span_id", "resource_ref",
    "action", "result", "status", "error_type", "error_code",
    "retry_count", "duration_ms", "dependency", "provider",
    "provenance_ref",
})
_METRIC_LABELS = frozenset({"operation_code", "bounded_context", "result", "status", "dependency"})
_CODE_ATTRIBUTES = frozenset({
    "operation_code", "bounded_context", "action", "result", "status",
    "error_type", "error_code", "dependency", "provider",
})
_HEX_IDENTITIES = {"request_id": 32, "trace_id": 32, "span_id": 16}
_CLASSIFICATIONS = frozenset({"public", "internal", "confidential", "restricted"})
_PURPOSES = frozenset({"operations", "performance", "reliability", "security_investigation"})
_SEVERITIES = frozenset({"DEBUG", "INFO", "WARN", "ERROR"})


def _require_match(value: str, pattern: re.Pattern[str], field_name: str) -> None:
    """Reject unbounded or ambiguous identity and code fields."""
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise ValueError(f"invalid {field_name}")


@dataclass(frozen=True)
class TelemetryConfig:
    """Explicit product identity and optional authenticated OTLP receiver."""

    service: str
    version: str
    environment: str
    source_revision: str
    receiver: str | None = None
    token: str | None = field(default=None, repr=False)
    queue_size: int = 2048

    def __post_init__(self) -> None:
        """Validate configuration before any provider or exporter exists."""
        for key in ("service", "environment"):
            _require_match(getattr(self, key), _IDENTITY, key)
        _require_match(self.version, _VERSION, "version")
        _require_match(self.source_revision, _REVISION, "source_revision")
        if not isinstance(self.queue_size, int) or not 16 <= self.queue_size <= 10_000:
            raise ValueError("invalid queue_size")
        if self.receiver is None:
            if self.token is not None:
                raise ValueError("token requires a receiver")
            return
        if not isinstance(self.receiver, str):
            raise ValueError("invalid receiver")
        parsed = urlsplit(self.receiver)
        try:
            valid_port = parsed.port is None or 1 <= parsed.port <= 65535
        except ValueError:
            valid_port = False
        if (
            parsed.scheme != "https" or not parsed.hostname or not valid_port
            or parsed.username or parsed.password or parsed.query or parsed.fragment
            or parsed.path not in ("", "/")
        ):
            raise ValueError("invalid receiver")
        if not isinstance(self.token, str) or not 16 <= len(self.token) <= 4096:
            raise ValueError("receiver requires a scoped token")


@dataclass(frozen=True)
class TelemetryEvent:
    """A structured signal whose fields must pass admission before export."""

    name: str
    severity: str
    classification: str
    purpose_code: str
    kind: str
    attributes: Mapping[str, str | int | float | bool] = field(default_factory=dict)


def _validate_attributes(attributes: Mapping[str, object], allowed: frozenset[str]) -> dict[str, object]:
    """Return a safe copy of bounded structured attributes."""
    if not isinstance(attributes, Mapping) or len(attributes) > 24:
        raise ValueError("invalid attributes")
    safe: dict[str, object] = {}
    for key, value in attributes.items():
        if key not in allowed:
            raise ValueError("unknown telemetry attribute")
        if key in ("retry_count", "duration_ms"):
            if type(value) not in (int, float) or not math.isfinite(value) or not 0 <= value <= 1_000_000_000:
                raise ValueError("invalid numeric telemetry attribute")
        elif type(value) is not str:
            raise ValueError("invalid telemetry attribute")
        elif key in _HEX_IDENTITIES:
            if re.fullmatch(rf"[0-9a-f]{{{_HEX_IDENTITIES[key]}}}", value) is None:
                raise ValueError("invalid correlation reference")
        elif key in _CODE_ATTRIBUTES:
            _require_match(value, _CODE, key)
        elif _REFERENCE.fullmatch(value) is None:
            raise ValueError("invalid opaque reference")
        safe[key] = value
    return safe


def validate_event(event: TelemetryEvent) -> TelemetryEvent:
    """Reject unknown, unbounded, or sensitive event content before export."""
    if not isinstance(event, TelemetryEvent):
        raise ValueError("invalid telemetry event")
    _require_match(event.name, _EVENT, "event name")
    if event.severity not in _SEVERITIES:
        raise ValueError("invalid severity")
    if event.classification not in _CLASSIFICATIONS:
        raise ValueError("invalid classification")
    if event.purpose_code not in _PURPOSES:
        raise ValueError("invalid purpose")
    if event.kind not in ("operational", "security"):
        raise ValueError("invalid signal kind")
    if event.kind == "security" and event.purpose_code != "security_investigation":
        raise ValueError("security signals require security purpose")
    _validate_attributes(event.attributes, _ATTRIBUTES)
    return event


class _LoggerPort:
    """Admit structured records without exposing the raw OTel logger."""

    def __init__(self, otel_logger: Any) -> None:
        self._logger = otel_logger
        self.dropped = 0

    def emit(self, event: TelemetryEvent) -> None:
        """Never fail product work for an ordinary export-path error."""
        validate_event(event)
        from opentelemetry._logs import SeverityNumber

        try:
            self._logger.emit(
                severity_number=getattr(SeverityNumber, event.severity),
                severity_text=event.severity,
                body=event.name,
                event_name=event.name,
                attributes={
                    **_validate_attributes(event.attributes, _ATTRIBUTES),
                    "cwl.classification": event.classification,
                    "cwl.purpose_code": event.purpose_code,
                    "cwl.kind": event.kind,
                    "cwl.schema_version": "1",
                },
            )
        except Exception:
            self.dropped += 1


class _TracerPort:
    """Start spans only with admitted names and attributes."""

    def __init__(self, tracer: Any) -> None:
        self._tracer = tracer

    def start_as_current_span(self, name: str, attributes: Mapping[str, object] | None = None) -> Any:
        """Return an OpenTelemetry span context manager with bounded input."""
        _require_match(name, _CODE, "span name")
        safe = _validate_attributes(attributes or {}, _ATTRIBUTES)
        return self._tracer.start_as_current_span(name, attributes=safe)


class _MeterPort:
    """Create counters whose labels have bounded cardinality."""

    def __init__(self, meter: Any) -> None:
        self._meter = meter

    def counter(self, name: str) -> Any:
        """Return a counter with an admitted-add operation."""
        _require_match(name, _CODE, "metric name")
        instrument = self._meter.create_counter(name)

        class Counter:
            """Small metric Port with a fixed label vocabulary."""

            def add(self, value: int, attributes: Mapping[str, object] | None = None) -> None:
                """Reject high-cardinality labels before recording."""
                if type(value) is not int or value < 0:
                    raise ValueError("invalid counter increment")
                instrument.add(value, attributes=_validate_attributes(attributes or {}, _METRIC_LABELS))

        return Counter()


@dataclass
class TelemetryRuntime:
    """Explicit provider lifetime and safe product-facing Ports."""

    tracer: _TracerPort
    meter: _MeterPort
    logger: _LoggerPort
    _providers: tuple[Any, Any, Any] = field(repr=False)

    def emit(self, event: TelemetryEvent) -> None:
        """Emit an admitted structured record."""
        self.logger.emit(event)

    def shutdown(self) -> None:
        """Flush and close providers at product shutdown."""
        for provider in self._providers:
            provider.shutdown()


def bootstrap(config: TelemetryConfig) -> TelemetryRuntime:
    """Construct isolated providers and opt into an authenticated OTLP receiver."""
    if not isinstance(config, TelemetryConfig):
        raise ValueError("invalid telemetry config")
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor
    from opentelemetry.sdk.metrics import MeterProvider
    from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
    from opentelemetry.sdk._logs import LoggerProvider
    from opentelemetry.sdk._logs.export import BatchLogRecordProcessor

    resource = Resource({
        "service.name": config.service,
        "service.version": config.version,
        "deployment.environment.name": config.environment,
        "cwl.source_revision": config.source_revision,
    })
    readers = []
    if config.receiver:
        from opentelemetry.exporter.otlp.proto.http.metric_exporter import OTLPMetricExporter

        headers = {"Authorization": f"Bearer {config.token}"}
        readers.append(PeriodicExportingMetricReader(
            OTLPMetricExporter(
                endpoint=config.receiver.rstrip("/") + "/v1/metrics", headers=headers, timeout=5,
            ),
            export_interval_millis=60_000,
        ))
    meter_provider = MeterProvider(resource=resource, metric_readers=readers, shutdown_on_exit=False)
    tracer_provider = TracerProvider(resource=resource, shutdown_on_exit=False)
    logger_provider = LoggerProvider(resource=resource, shutdown_on_exit=False)
    if config.receiver:
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
        from opentelemetry.exporter.otlp.proto.http._log_exporter import OTLPLogExporter

        headers = {"Authorization": f"Bearer {config.token}"}
        tracer_provider.add_span_processor(BatchSpanProcessor(
            OTLPSpanExporter(
                endpoint=config.receiver.rstrip("/") + "/v1/traces", headers=headers, timeout=5,
            ),
            max_queue_size=config.queue_size,
            max_export_batch_size=min(128, config.queue_size),
        ))
        logger_provider.add_log_record_processor(BatchLogRecordProcessor(
            OTLPLogExporter(
                endpoint=config.receiver.rstrip("/") + "/v1/logs", headers=headers, timeout=5,
            ),
            max_queue_size=config.queue_size,
            max_export_batch_size=min(128, config.queue_size),
        ))
    return TelemetryRuntime(
        tracer=_TracerPort(tracer_provider.get_tracer(config.service, config.version)),
        meter=_MeterPort(meter_provider.get_meter(config.service, config.version)),
        logger=_LoggerPort(logger_provider.get_logger(config.service, config.version)),
        _providers=(tracer_provider, meter_provider, logger_provider),
    )
