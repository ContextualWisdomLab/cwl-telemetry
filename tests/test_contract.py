"""Executable version-one safety contract for the shared runtime."""

from __future__ import annotations

import subprocess
import sys

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


def test_bootstrap_is_explicit_and_transaction_survives_export_failure(monkeypatch) -> None:
    """Ordinary work remains successful when the OTLP export path fails."""
    from cwl_telemetry import TelemetryConfig, TelemetryEvent, bootstrap

    config = TelemetryConfig(
        service="svc", version="1", environment="test", source_revision="a" * 40,
    )
    runtime = bootstrap(config)
    assert runtime.tracer is not None
    assert runtime.meter is not None
    assert runtime.logger is not None
    with runtime.tracer.start_as_current_span("work"):
        assert 2 + 2 == 4
    runtime.emit(TelemetryEvent(
        name="work.completed", severity="INFO", classification="internal",
        purpose_code="operations", kind="operational", attributes={"operation_code": "work"},
    ))
    runtime.shutdown()
