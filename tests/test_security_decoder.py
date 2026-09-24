"""Hostile OTLP decoder and durable normalized security outbox checks."""

from __future__ import annotations

import sqlite3
import socket
import ssl
import subprocess
import sys
import threading
import time
import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

import pytest
from opentelemetry.proto.collector.logs.v1.logs_service_pb2 import ExportLogsServiceRequest

from cwl_telemetry.security import (
    decode_security_export, mark_security_delivered, pending_security_events,
)
from cwl_telemetry.security_consumer import make_security_server
from cwl_telemetry.security_sender import deliver_pending


NOW = 1_000_000_000_000_000_000


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
        assert pending_security_events(connection) == []
        with pytest.raises(ValueError, match="unknown"):
            mark_security_delivered(connection, "b" * 32)
        request = _request()
        payload = request.SerializeToString()
        accepted = decode_security_export(payload, authenticated_tenant="tenant_1", replay_db=connection, now_ns=NOW)
        assert accepted[0]["event_name"] == "authentication.denied"
        assert pending_security_events(connection) == accepted
        assert decode_security_export(payload, authenticated_tenant="tenant_1", replay_db=connection, now_ns=NOW) == accepted
        assert pending_security_events(connection) == accepted
        assert decode_security_export(payload, authenticated_tenant="tenant_1", replay_db=connection, now_ns=NOW + 3_600_000_000_000) == accepted
        conflicting = _request()
        conflicting.resource_logs[0].scope_logs[0].log_records[0].attributes[6].value.string_value = "different"
        with pytest.raises(ValueError, match="conflicting"):
            decode_security_export(conflicting.SerializeToString(), authenticated_tenant="tenant_1", replay_db=connection, now_ns=NOW)

        for mutation in (
            lambda item: setattr(item.resource_logs[0].scope_logs[0].log_records[0], "time_unix_nano", NOW - 8 * 24 * 3_600_000_000_000),
            lambda item: setattr(item.resource_logs[0].scope_logs[0].log_records[0], "time_unix_nano", NOW + 301_000_000_000),
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


def test_https_consumer_admits_only_tenant_bound_otlp_and_recovers(tmp_path: Path) -> None:
    """HTTP admission and a full outbox preserve records through receiver restart."""
    certificate = tmp_path / "server.crt"
    private_key = tmp_path / "server.key"
    subprocess.run([
        "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
        "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1",
        "-keyout", str(private_key), "-out", str(certificate), "-days", "1",
    ], check=True, capture_output=True)
    token_file = tmp_path / "token"
    token_file.write_text("synthetic-consumer-token-12345\n")
    outbox = tmp_path / "outbox.sqlite"
    server = make_security_server(
        ("127.0.0.1", 0), certificate=certificate, private_key=private_key,
        token_file=token_file, tenant_ref="tenant_1", outbox=outbox, max_pending=1,
    )
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        url = f"https://127.0.0.1:{server.server_port}/v1/logs"
        context = ssl.create_default_context(cafile=str(certificate))

        def post(body: bytes, *, token: str | None = "synthetic-consumer-token-12345",
                 content_type: str = "application/x-protobuf", target: str = url,
                 content_encoding: str | None = None) -> int:
            headers = {"Content-Type": content_type}
            if token is not None:
                headers["Authorization"] = f"Bearer {token}"
            if content_encoding is not None:
                headers["Content-Encoding"] = content_encoding
            try:
                with urlopen(Request(target, data=body, headers=headers), context=context, timeout=3) as response:
                    return response.status
            except HTTPError as error:
                error.close()
                return error.code

        message = _request()
        message.resource_logs[0].scope_logs[0].log_records[0].time_unix_nano = time.time_ns()
        body = message.SerializeToString()
        server.RequestHandlerClass.timeout = 1
        with socket.create_connection(("127.0.0.1", server.server_port), timeout=1):
            time.sleep(0.05)
            assert post(body) == 200  # idle unauthenticated TCP peer cannot hold the receiver
        with socket.create_connection(("127.0.0.1", server.server_port), timeout=1) as raw:
            with context.wrap_socket(raw, server_hostname="localhost"):
                time.sleep(0.05)
                assert post(body) == 200  # completed TLS without HTTP has the same bound
        assert post(body, token=None) == 401
        assert post(body, token="wrong-token") == 401
        assert post(body, content_type="text/plain") == 415
        assert post(body, content_encoding="gzip") == 415
        assert post(b"invalid protobuf") == 400
        assert post(b"x" * 65_537) == 413
        try:
            assert post(body, target=url.replace("https:", "http:")) != 200
        except (OSError, URLError):
            pass
        assert post(body) == 200
        assert post(body) == 200  # idempotent Collector retry
        assert outbox.stat().st_mode & 0o077 == 0
        wrong_tenant = _request()
        wrong_tenant.resource_logs[0].scope_logs[0].log_records[0].time_unix_nano = time.time_ns()
        wrong_tenant.resource_logs[0].scope_logs[0].log_records[0].attributes[4].value.string_value = "other_tenant"
        assert post(wrong_tenant.SerializeToString()) == 400
        second = _request()
        record = second.resource_logs[0].scope_logs[0].log_records[0]
        record.time_unix_nano = time.time_ns()
        record.attributes[5].value.string_value = "c" * 32
        assert post(second.SerializeToString()) == 503  # bounded pending outbox
        mixed = _request()
        mixed.resource_logs[0].scope_logs[0].log_records[0].time_unix_nano = message.resource_logs[0].scope_logs[0].log_records[0].time_unix_nano
        mixed.resource_logs[0].scope_logs[0].log_records.add().CopyFrom(record)
        assert post(mixed.SerializeToString()) == 503
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=5)
    with sqlite3.connect(outbox) as recovered:
        assert len(pending_security_events(recovered)) == 1
        mark_security_delivered(recovered, "b" * 32)
        assert pending_security_events(recovered) == []
        decode_security_export(
            mixed.SerializeToString(), authenticated_tenant="tenant_1",
            replay_db=recovered, max_pending=1,
        )
        assert [row["event_id"] for row in pending_security_events(recovered)] == ["c" * 32]


def test_siem_handoff_keeps_outbox_pending_until_exact_https_ack(tmp_path: Path) -> None:
    """Outage, wrong acknowledgement, and redirect cannot acknowledge an event."""
    certificate = tmp_path / "gateway.crt"
    private_key = tmp_path / "gateway.key"
    subprocess.run([
        "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
        "-subj", "/CN=localhost", "-addext", "subjectAltName=IP:127.0.0.1",
        "-keyout", str(private_key), "-out", str(certificate), "-days", "1",
    ], check=True, capture_output=True)
    outbox = tmp_path / "security.sqlite"
    with sqlite3.connect(outbox) as connection:
        decode_security_export(
            _request().SerializeToString(), authenticated_tenant="tenant_1",
            replay_db=connection, now_ns=NOW,
        )
    outbox.chmod(0o600)
    mode = {"value": "outage"}
    captured = []
    token = "synthetic-siem-token-12345"

    class Gateway(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def do_POST(self):
            body = self.rfile.read(int(self.headers["Content-Length"]))
            captured.append((self.path, self.headers.get("Authorization"),
                             self.headers.get("Idempotency-Key"), body))
            if mode["value"] == "outage":
                self.send_response(503)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            if mode["value"] == "redirect":
                self.send_response(307)
                self.send_header("Location", "https://untrusted.example/v1/security-events")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            event_id = "f" * 32 if mode["value"] == "wrong_ack" else "b" * 32
            response = json.dumps({"accepted": True, "event_id": event_id}).encode()
            if mode["value"] == "duplicate_ack":
                response = response[:-1] + f', "event_id": "{event_id}"}}'.encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(response)))
            self.end_headers()
            self.wfile.write(response)

    server = HTTPServer(("127.0.0.1", 0), Gateway)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(certificate), str(private_key))
    server.socket = context.wrap_socket(server.socket, server_side=True)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    gateway = f"https://127.0.0.1:{server.server_port}"
    try:
        rejected_cli = subprocess.run(
            [sys.executable, "-m", "cwl_telemetry.security_sender",
             "--outbox", str(outbox), "--gateway", "http://127.0.0.1"],
            input=token + "\n", capture_output=True, text=True, check=False,
        )
        assert rejected_cli.returncode != 0
        assert token not in rejected_cli.stderr
        with pytest.raises(ValueError, match="origin"):
            deliver_pending(outbox, gateway="http://127.0.0.1", token=token)
        with pytest.raises(HTTPError):
            deliver_pending(outbox, gateway=gateway, token=token, ca_file=certificate)
        mode["value"] = "wrong_ack"
        with pytest.raises(ValueError, match="acknowledgement"):
            deliver_pending(outbox, gateway=gateway, token=token, ca_file=certificate)
        mode["value"] = "duplicate_ack"
        with pytest.raises(ValueError, match="acknowledgement"):
            deliver_pending(outbox, gateway=gateway, token=token, ca_file=certificate)
        mode["value"] = "redirect"
        with pytest.raises(HTTPError):
            deliver_pending(outbox, gateway=gateway, token=token, ca_file=certificate)
        with sqlite3.connect(outbox) as connection:
            assert [row["event_id"] for row in pending_security_events(connection)] == ["b" * 32]
        mode["value"] = "ready"
        assert deliver_pending(outbox, gateway=gateway, token=token, ca_file=certificate) == 1
        assert deliver_pending(outbox, gateway=gateway, token=token, ca_file=certificate) == 0
        assert captured[-1][:3] == ("/v1/security-events", f"Bearer {token}", "b" * 32)
        assert json.loads(captured[-1][3])["event_name"] == "authentication.denied"
        with sqlite3.connect(outbox) as connection:
            assert pending_security_events(connection) == []
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=5)
