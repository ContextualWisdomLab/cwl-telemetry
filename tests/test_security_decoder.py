"""Hostile OTLP decoder and durable normalized security outbox checks."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest
from opentelemetry.proto.collector.logs.v1.logs_service_pb2 import ExportLogsServiceRequest

from cwl_telemetry.security import (
    decode_security_export, mark_security_delivered, pending_security_events,
)


NOW = 1_000_000_000_000


def _attribute(items, key: str, value: str) -> None:
    item = items.add()
    item.key = key
    item.value.string_value = value


def _request() -> ExportLogsServiceRequest:
    message = ExportLogsServiceRequest()
    resource_logs = message.resource_logs.add()
    for key, value in (
        ("service.name", "canary"), ("service.version", "0.1.0"),
        ("deployment.environment.name", "test"), ("cwl.source_revision", "a" * 40),
    ):
        _attribute(resource_logs.resource.attributes, key, value)
    record = resource_logs.scope_logs.add().log_records.add()
    record.time_unix_nano = NOW
    record.severity_number = 13
    record.severity_text = "WARN"
    record.event_name = "authentication.denied"
    record.body.string_value = record.event_name
    for key, value in (
        ("cwl.schema_version", "1"), ("cwl.kind", "security"),
        ("cwl.classification", "internal"),
        ("cwl.purpose_code", "security_investigation"),
        ("tenant_ref", "tenant_1"), ("event_id", "b" * 32),
        ("operation_code", "login"),
    ):
        _attribute(record.attributes, key, value)
    return message


def test_security_decoder_rejects_hostile_records_and_persists_outbox(tmp_path: Path) -> None:
    """Only one bounded, fresh, tenant-bound event reaches the durable outbox."""
    database = tmp_path / "replay.sqlite"
    with sqlite3.connect(database) as connection:
        request = _request()
        payload = request.SerializeToString()
        accepted = decode_security_export(payload, authenticated_tenant="tenant_1", replay_db=connection, now_ns=NOW)
        assert accepted[0]["event_name"] == "authentication.denied"
        assert pending_security_events(connection) == accepted
        with pytest.raises(ValueError, match="replayed"):
            decode_security_export(payload, authenticated_tenant="tenant_1", replay_db=connection, now_ns=NOW)

        for mutation in (
            lambda item: setattr(item.resource_logs[0].scope_logs[0].log_records[0], "time_unix_nano", NOW - 301_000_000_000),
            lambda item: setattr(item.resource_logs[0].scope_logs[0].log_records[0], "event_name", "debug.dump"),
            lambda item: setattr(item.resource_logs[0].scope_logs[0].log_records[0], "severity_text", "INFO"),
            lambda item: setattr(item.resource_logs[0].scope_logs[0].log_records[0].attributes[0].value, "string_value", "2"),
        ):
            hostile = _request()
            mutation(hostile)
            with pytest.raises(ValueError):
                decode_security_export(hostile.SerializeToString(), authenticated_tenant="tenant_1", replay_db=connection, now_ns=NOW)
        with pytest.raises(ValueError, match="tenant"):
            decode_security_export(payload, authenticated_tenant="other_tenant", replay_db=connection, now_ns=NOW)
        with pytest.raises(ValueError):
            decode_security_export(b"bad protobuf", authenticated_tenant="tenant_1", replay_db=connection, now_ns=NOW)
        with pytest.raises(ValueError):
            decode_security_export(b"x" * 65_537, authenticated_tenant="tenant_1", replay_db=connection, now_ns=NOW)
        assert pending_security_events(connection) == accepted

    with sqlite3.connect(database) as recovered:
        assert pending_security_events(recovered) == accepted
        mark_security_delivered(recovered, "b" * 32)
        assert pending_security_events(recovered) == []
        with pytest.raises(ValueError):
            mark_security_delivered(recovered, "b" * 32)


def test_real_sdk_security_log_decodes_without_extra_resource_fields(tmp_path: Path) -> None:
    """The producer's actual OTLP encoding satisfies the consumer contract."""
    from opentelemetry.exporter.otlp.proto.common._internal._log_encoder import encode_logs
    from opentelemetry.sdk._logs.export import LogExportResult, SimpleLogRecordProcessor
    from cwl_telemetry import TelemetryConfig, TelemetryEvent, bootstrap

    captured = []

    class Capture:
        def export(self, batch):
            captured.extend(batch)
            return LogExportResult.SUCCESS

        def shutdown(self):
            pass

        def force_flush(self, timeout_millis=30000):
            return True

    runtime = bootstrap(TelemetryConfig(
        service="canary", version="0.1.0", environment="test", source_revision="a" * 40,
    ))
    runtime._providers[2].add_log_record_processor(SimpleLogRecordProcessor(Capture()))
    runtime.emit(TelemetryEvent(
        name="authentication.denied", severity="WARN", classification="internal",
        purpose_code="security_investigation", kind="security",
        attributes={"tenant_ref": "tenant_1", "event_id": "c" * 32, "operation_code": "login"},
    ))
    payload = encode_logs(captured).SerializeToString()
    with sqlite3.connect(tmp_path / "real-sdk.sqlite") as connection:
        rows = decode_security_export(payload, authenticated_tenant="tenant_1", replay_db=connection)
        assert rows[0]["event_id"] == "c" * 32
    runtime.shutdown()
