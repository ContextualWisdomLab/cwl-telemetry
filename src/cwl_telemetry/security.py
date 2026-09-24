"""Strict OTLP log projection for a separate normalized security consumer."""

from __future__ import annotations

import json
import sqlite3
import time
from typing import Any

from google.protobuf.message import DecodeError
from opentelemetry.proto.collector.logs.v1.logs_service_pb2 import ExportLogsServiceRequest

from . import TelemetryConfig, TelemetryEvent, validate_event


_RESOURCE_KEYS = frozenset({
    "service.name", "service.version", "deployment.environment.name", "cwl.source_revision",
})
_SEVERITY_NUMBERS = {"DEBUG": range(5, 9), "INFO": range(9, 13),
                     "WARN": range(13, 17), "ERROR": range(17, 21)}
_MAX_AGE_NS = 7 * 24 * 60 * 60 * 1_000_000_000
_FUTURE_SKEW_NS = 5 * 60 * 1_000_000_000


def _attributes(items: Any) -> dict[str, str | int | float | bool]:
    """Reject duplicate, nested, and untyped OTLP attributes."""
    result: dict[str, str | int | float | bool] = {}
    for item in items:
        if item.key in result:
            raise ValueError("duplicate telemetry attribute")
        kind = item.value.WhichOneof("value")
        if kind not in ("string_value", "int_value", "double_value", "bool_value"):
            raise ValueError("unsupported telemetry attribute")
        result[item.key] = getattr(item.value, kind)
    return result


def _ensure_outbox(replay_db: sqlite3.Connection) -> None:
    replay_db.execute(
        "CREATE TABLE IF NOT EXISTS security_event_outbox "
        "(event_id TEXT PRIMARY KEY, record_json TEXT NOT NULL, time_unix_nano INTEGER NOT NULL, "
        "delivered INTEGER NOT NULL DEFAULT 0)"
    )


def decode_security_export(
    payload: bytes, *, authenticated_tenant: str, replay_db: sqlite3.Connection,
    now_ns: int | None = None, max_pending: int = 100_000,
) -> list[dict[str, Any]]:
    """Validate one authenticated OTLP batch and durably deduplicate event IDs.

    The caller owns TLS and bearer authentication, and must supply the tenant
    bound to that credential. This decoder never executes domain commands.
    """
    if not isinstance(payload, bytes) or not 0 < len(payload) <= 65_536:
        raise ValueError("invalid OTLP body size")
    if not isinstance(authenticated_tenant, str) or not authenticated_tenant:
        raise ValueError("missing authenticated tenant")
    if type(max_pending) is not int or not 1 <= max_pending <= 1_000_000:
        raise ValueError("invalid security outbox capacity")
    request = ExportLogsServiceRequest()
    try:
        request.ParseFromString(payload)
    except DecodeError as error:
        raise ValueError("invalid OTLP protobuf") from error
    now = time.time_ns() if now_ns is None else now_ns
    if not isinstance(now, int) or now <= 0:
        raise ValueError("invalid receiver time")
    projected: list[dict[str, Any]] = []
    for resource_logs in request.resource_logs:
        resource = _attributes(resource_logs.resource.attributes)
        if resource.keys() != _RESOURCE_KEYS or any(type(value) is not str for value in resource.values()):
            raise ValueError("invalid source resource")
        TelemetryConfig(
            service=resource["service.name"], version=resource["service.version"],
            environment=resource["deployment.environment.name"],
            source_revision=resource["cwl.source_revision"],
        )
        for scope_logs in resource_logs.scope_logs:
            for record in scope_logs.log_records:
                if (record.dropped_attributes_count or record.time_unix_nano <= 0
                        or now - record.time_unix_nano > _MAX_AGE_NS
                        or record.time_unix_nano - now > _FUTURE_SKEW_NS):
                    raise ValueError("incomplete or stale security event")
                attributes = _attributes(record.attributes)
                if attributes.pop("cwl.schema_version", None) != "1" or attributes.pop("cwl.kind", None) != "security":
                    raise ValueError("unsupported security schema")
                classification = attributes.pop("cwl.classification", None)
                purpose = attributes.pop("cwl.purpose_code", None)
                if (record.body.WhichOneof("value") != "string_value"
                        or record.body.string_value != record.event_name
                        or record.severity_number not in _SEVERITY_NUMBERS.get(record.severity_text, ())):
                    raise ValueError("invalid security record")
                if attributes.get("tenant_ref") != authenticated_tenant:
                    raise ValueError("security tenant mismatch")
                event = TelemetryEvent(
                    name=record.event_name, severity=record.severity_text,
                    classification=classification, purpose_code=purpose,
                    kind="security", attributes=attributes,
                )
                validate_event(event)
                projected.append({
                    "schema_version": "1", "event_id": attributes["event_id"],
                    "event_name": event.name, "time_unix_nano": record.time_unix_nano,
                    "severity": event.severity, "classification": event.classification,
                    "purpose_code": event.purpose_code, "service": resource["service.name"],
                    "service_version": resource["service.version"],
                    "environment": resource["deployment.environment.name"],
                    "source_revision": resource["cwl.source_revision"],
                    "attributes": dict(attributes),
                })
    if not projected:
        raise ValueError("empty security batch")
    _ensure_outbox(replay_db)
    try:
        replay_db.execute("BEGIN IMMEDIATE")
        replay_db.execute(
            "DELETE FROM security_event_outbox WHERE delivered = 1 AND time_unix_nano < ?",
            (now - _MAX_AGE_NS,),
        )
        new_rows = []
        seen = {}
        for row in projected:
            encoded = json.dumps(row, sort_keys=True)
            event_id = row["event_id"]
            previous = seen.get(event_id)
            if previous is None:
                existing = replay_db.execute(
                    "SELECT record_json FROM security_event_outbox WHERE event_id = ?", (event_id,),
                ).fetchone()
                previous = existing[0] if existing else None
            if previous is not None and previous != encoded:
                raise ValueError("conflicting security event ID")
            if previous is None:
                new_rows.append((event_id, encoded, row["time_unix_nano"]))
            seen[event_id] = encoded
        pending = replay_db.execute(
            "SELECT COUNT(*) FROM security_event_outbox WHERE delivered = 0"
        ).fetchone()[0]
        if pending + len(new_rows) > max_pending:
            raise ValueError("security outbox full")
        replay_db.executemany(
            "INSERT INTO security_event_outbox (event_id, record_json, time_unix_nano) VALUES (?, ?, ?)",
            new_rows,
        )
        replay_db.commit()
    except Exception:
        replay_db.rollback()
        raise
    return projected


def pending_security_events(replay_db: sqlite3.Connection, limit: int = 100) -> list[dict[str, Any]]:
    """Read undelivered normalized records for a separate SIEM sender."""
    if not 1 <= limit <= 1000:
        raise ValueError("invalid pending batch size")
    _ensure_outbox(replay_db)
    rows = replay_db.execute(
        "SELECT record_json FROM security_event_outbox WHERE delivered = 0 ORDER BY rowid LIMIT ?",
        (limit,),
    )
    return [json.loads(row[0]) for row in rows]


def mark_security_delivered(replay_db: sqlite3.Connection, event_id: str) -> None:
    """Mark one record only after an authenticated SIEM acknowledgement."""
    _ensure_outbox(replay_db)
    with replay_db:
        changed = replay_db.execute(
            "UPDATE security_event_outbox SET delivered = 1 WHERE event_id = ? AND delivered = 0",
            (event_id,),
        ).rowcount
    if changed != 1:
        raise ValueError("unknown or already delivered security event")
