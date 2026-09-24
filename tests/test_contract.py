"""Executable version-one safety contract for the shared runtime."""

from __future__ import annotations

import subprocess
import sys
import threading

import pytest


def test_import_has_no_network_or_worker_side_effect() -> None:
    """Merely importing the package cannot connect or start export workers."""
    code = """
import socket, threading
def deny(*args, **kwargs):
    raise AssertionError('import attempted network traffic')
socket.socket.connect = deny
before = {thread.ident for thread in threading.enumerate()}
import cwl_telemetry
assert {thread.ident for thread in threading.enumerate()} == before
"""
    subprocess.run([sys.executable, "-c", code], check=True)


def test_config_requires_identity_and_secure_receiver() -> None:
    """A receiver and source identity are validated before startup."""
    from cwl_telemetry import TelemetryConfig

    with pytest.raises(ValueError):
        TelemetryConfig(service="", version="1", environment="dev", source_revision="a" * 40)
    with pytest.raises(ValueError):
        TelemetryConfig(service="svc", version="1", environment="dev", source_revision="missing")
    with pytest.raises(ValueError):
        TelemetryConfig(
            service="svc", version="1", environment="dev", source_revision="a" * 40,
            receiver="http://collector.example:4318",
        )


def test_event_admission_rejects_raw_secrets_pii_and_unknown_fields() -> None:
    """Only bounded, classified event fields enter the export path."""
    from cwl_telemetry import TelemetryEvent, validate_event

    valid = TelemetryEvent(
        name="request.denied", severity="WARN", classification="internal",
        purpose_code="security_investigation", kind="security",
        attributes={"operation_code": "login", "tenant_ref": "t_123"},
    )
    assert validate_event(valid) is valid
    for attributes in (
        {"Authorization": "Bearer secret"},
        {"operation_code": "person@example.com"},
        {"unknown": "value"},
        {"operation_code": "x" * 200},
    ):
        with pytest.raises(ValueError):
            validate_event(TelemetryEvent(
                name="request.denied", severity="WARN", classification="internal",
                purpose_code="security_investigation", kind="security",
                attributes=attributes,
            ))


def test_bootstrap_is_explicit_and_product_work_completes() -> None:
    """An in-process runtime exposes the three safe Ports."""
    from cwl_telemetry import TelemetryConfig, TelemetryEvent, bootstrap

    config = TelemetryConfig(
        service="svc", version="1", environment="test", source_revision="a" * 40,
    )
    runtime = bootstrap(config)
    assert runtime.tracer is not None
    assert runtime.tracer_provider is runtime._providers[0]
    assert runtime.meter is not None
    assert runtime.logger is not None
    with runtime.tracer.start_as_current_span("work"):
        assert 2 + 2 == 4
    runtime.emit(TelemetryEvent(
        name="work.completed", severity="INFO", classification="internal",
        purpose_code="operations", kind="operational", attributes={"operation_code": "work"},
    ))
    runtime.shutdown()


def test_logger_failure_does_not_fail_work_but_invalid_event_does() -> None:
    """Delivery failure is noncritical; admission failure remains visible."""
    from cwl_telemetry import TelemetryConfig, TelemetryEvent, bootstrap

    runtime = bootstrap(TelemetryConfig(
        service="svc", version="1", environment="test", source_revision="a" * 40,
    ))

    class FailingLogger:
        """Synthetic failing sink behind the real product Port."""

        def emit(self, **_kwargs):
            """Fail after admission, like a broken exporter."""
            raise OSError("receiver unavailable")

    runtime.logger._logger = FailingLogger()
    event = TelemetryEvent(
        name="work.completed", severity="INFO", classification="internal",
        purpose_code="operations", kind="operational", attributes={"operation_code": "work"},
    )
    runtime.emit(event)
    assert runtime.logger.dropped == 1
    with pytest.raises(ValueError):
        runtime.emit(TelemetryEvent(
            name="work.completed", severity="INFO", classification="internal",
            purpose_code="operations", kind="operational", attributes={"Authorization": "secret"},
        ))
    runtime.shutdown()


def test_receiver_outage_keeps_transaction_and_credentials_private(caplog) -> None:
    """An unreachable local TLS receiver cannot turn a product action into failure."""
    from cwl_telemetry import TelemetryConfig, TelemetryEvent, bootstrap

    token = "sentinel-private-token-12345"
    config = TelemetryConfig(
        service="svc", version="1", environment="test", source_revision="a" * 40,
        receiver="https://127.0.0.1:1", token=token, queue_size=16,
    )
    assert token not in repr(config)
    runtime = bootstrap(config)
    with runtime.tracer.start_as_current_span("work"):
        assert 2 + 2 == 4
    runtime.emit(TelemetryEvent(
        name="work.completed", severity="INFO", classification="internal",
        purpose_code="operations", kind="operational", attributes={"operation_code": "work"},
    ))
    runtime.shutdown()
    assert token not in caplog.text


def test_metric_and_span_ports_reject_unbounded_attributes() -> None:
    """Product code cannot add arbitrary span content or metric labels."""
    from cwl_telemetry import TelemetryConfig, bootstrap

    runtime = bootstrap(TelemetryConfig(
        service="svc", version="1", environment="test", source_revision="a" * 40,
        metric_names=frozenset({"work_total"}), operation_codes=frozenset({"work"}),
    ))
    with pytest.raises(ValueError):
        runtime.tracer.start_as_current_span("work", {"prompt": "secret"})
    counter = runtime.meter.counter("work_total")
    with pytest.raises(ValueError):
        counter.add(1, {"tenant_ref": "t_123"})
    counter.add(1, {"operation_code": "work", "status": "success"})
    with pytest.raises(ValueError):
        counter.add(1, {"operation_code": "per_user_123"})
    with pytest.raises(ValueError):
        runtime.meter.counter("unregistered_total")
    runtime.shutdown()


def test_receiver_rejects_url_control_characters_and_label_sets() -> None:
    """Configuration cannot smuggle a different endpoint or unlimited labels."""
    from cwl_telemetry import TelemetryConfig

    base = dict(service="svc", version="1", environment="test", source_revision="a" * 40)
    with pytest.raises(ValueError):
        TelemetryConfig(**base, receiver="https://collector.example\n.evil", token="x" * 16)
    with pytest.raises(ValueError):
        TelemetryConfig(**base, metric_names=["same", "same"])
    with pytest.raises(ValueError):
        TelemetryConfig(**base, operation_codes={f"item_{n}" for n in range(129)})


def test_w3c_trace_propagation_preserves_identity_without_baggage() -> None:
    """A remote parent is correlated without copying arbitrary inbound headers."""
    from opentelemetry.context import attach, detach
    from cwl_telemetry import TelemetryConfig, bootstrap

    runtime = bootstrap(TelemetryConfig(
        service="svc", version="1", environment="test", source_revision="a" * 40,
    ))
    parent = "00-" + "a" * 32 + "-" + "b" * 16 + "-01"
    context = runtime.extract_trace({"traceparent": parent, "baggage": "person@example.com"})
    token = attach(context)
    try:
        with runtime.tracer.start_as_current_span("work"):
            outbound = runtime.inject_trace()
    finally:
        detach(token)
    assert outbound["traceparent"].split("-")[1] == "a" * 32
    assert set(outbound) == {"traceparent"}
    assert runtime.inject_trace() == {}
    assert runtime.extract_trace({"traceparent": "garbage"}) is not None
    runtime.shutdown()


def test_resource_identity_is_exact_and_private() -> None:
    """Resource identity uses the caller's exact build/source revision."""
    from cwl_telemetry import TelemetryConfig, bootstrap

    runtime = bootstrap(TelemetryConfig(
        service="svc", version="1.2.3", environment="prod", source_revision="a" * 40,
    ))
    resource = runtime._providers[0].resource.attributes
    assert resource["service.name"] == "svc"
    assert resource["service.version"] == "1.2.3"
    assert resource["deployment.environment.name"] == "prod"
    assert resource["cwl.source_revision"] == "a" * 40
    runtime.shutdown()


def test_bounded_span_queue_reports_saturation_and_recovers(monkeypatch, caplog) -> None:
    """A stuck receiver drops old spans without blocking work; newer work drains."""
    from opentelemetry.exporter.otlp.proto.http import trace_exporter
    from opentelemetry.sdk.trace.export import SpanExportResult
    from cwl_telemetry import TelemetryConfig, bootstrap

    release = threading.Event()
    exported: list[str] = []

    class PausedExporter:
        def __init__(self, **_kwargs):
            pass

        def export(self, spans):
            release.wait(3)
            exported.extend(span.name for span in spans)
            return SpanExportResult.SUCCESS

        def shutdown(self):
            pass

        def force_flush(self, timeout_millis=30000):
            return True

    monkeypatch.setattr(trace_exporter, "OTLPSpanExporter", PausedExporter)
    runtime = bootstrap(TelemetryConfig(
        service="svc", version="1", environment="test", source_revision="a" * 40,
        receiver="https://collector.example", token="synthetic-token-12345", queue_size=16,
    ))
    for _ in range(80):
        with runtime.tracer.start_as_current_span("saturated"):
            pass
    with runtime.tracer.start_as_current_span("recovered"):
        pass
    release.set()
    runtime.shutdown()
    assert "Queue full, dropping Span" in caplog.text
    assert "recovered" in exported
    assert len(exported) < 81
