"""Real Collector admission canary with synthetic local-only telemetry."""

from __future__ import annotations

import os
import platform
import re
import sqlite3
import ssl
import subprocess
import tempfile
import threading
import time
import uuid
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

import pytest
from opentelemetry.proto.collector.trace.v1.trace_service_pb2 import ExportTraceServiceRequest
from opentelemetry.proto.collector.logs.v1.logs_service_pb2 import ExportLogsServiceRequest
from cwl_telemetry import TelemetryConfig, TelemetryEvent, bootstrap
from cwl_telemetry.security import pending_security_events
from cwl_telemetry.security_consumer import make_security_server


IMAGE = "otel/opentelemetry-collector-contrib@sha256:fd328de2552466ad78385e1b1289c3f2402b1c45f265b252aab1955b42845ac1"
ALPINE = "alpine@sha256:14358309a308569c32bdc37e2e0e9694be33a9d99e68afb0f5ff33cc1f695dce"
CONFIG = Path(__file__).parents[1] / "collector" / "canary.yaml"
PRODUCTION_CONFIG = CONFIG.with_name("production.yaml")


def _run(*args: str) -> str:
    """Run one local fixture command without echoing its secret-bearing input."""
    return subprocess.check_output(args, text=True, stderr=subprocess.DEVNULL).strip()


def _request(url: str, body: bytes, *, token: str | None, content_type: str, context: ssl.SSLContext) -> int:
    """Return the receiver's HTTP status, including deliberate rejections."""
    headers = {"Content-Type": content_type}
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    request = Request(url, data=body, headers=headers, method="POST")
    try:
        with urlopen(request, context=context, timeout=2) as response:
            return response.status
    except HTTPError as error:
        error.close()
        return error.code


@pytest.mark.collector
def test_collector_rejects_invalid_tls_auth_type_size_and_payload() -> None:
    """The pinned real receiver accepts only bounded authenticated OTLP over TLS."""
    with tempfile.TemporaryDirectory() as temp:
        secret_dir = Path(temp)
        token = "synthetic-local-canary-token-12345"
        (secret_dir / "otlp_token").write_text(token + "\n", encoding="utf-8")
        _run(
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1",
            "-keyout", str(secret_dir / "server.key"), "-out", str(secret_dir / "server.crt"),
            "-days", "1",
        )
        os.chmod(secret_dir / "server.key", 0o644)  # synthetic canary key copied into a non-root container
        # docker cp also works when a remote Docker context cannot bind this
        # workspace path; all copied credentials are synthetic and short-lived.
        container = _run(
            "docker", "create", "-p", "127.0.0.1::4318", IMAGE,
            "--config=/config.yaml",
        )
        try:
            for source in (CONFIG, secret_dir / "otlp_token", secret_dir / "server.crt", secret_dir / "server.key"):
                _run("docker", "cp", str(source), f"{container}:/{source.name if source != CONFIG else 'config.yaml'}")
            _run("docker", "start", container)
            port = _run("docker", "port", container, "4318/tcp").rsplit(":", 1)[-1]
            url = f"https://127.0.0.1:{port}/v1/traces"
            context = ssl.create_default_context(cafile=str(secret_dir / "server.crt"))
            message = ExportTraceServiceRequest()
            span = message.resource_spans.add().scope_spans.add().spans.add()
            span.name = "canary"
            span.trace_id = bytes.fromhex("a" * 32)
            span.span_id = bytes.fromhex("b" * 16)
            span.start_time_unix_nano = time.time_ns()
            span.end_time_unix_nano = span.start_time_unix_nano + 1
            body = message.SerializeToString()

            last_status = None
            for _ in range(100):
                try:
                    last_status = _request(url, body, token=token, content_type="application/x-protobuf", context=context)
                    if last_status == 200:
                        break
                except (OSError, URLError):
                    pass
                time.sleep(0.1)
            else:
                result = subprocess.run(["docker", "logs", container], capture_output=True, text=True, check=False)
                logs = (result.stdout + result.stderr).replace(token, "<redacted>")
                pytest.fail(f"Collector did not admit valid OTLP (status={last_status}): {logs[-1200:]}")

            assert _request(url, body, token=None, content_type="application/x-protobuf", context=context) in (401, 403)
            assert _request(url, body, token="wrong-token", content_type="application/x-protobuf", context=context) in (401, 403)
            assert _request(url, body, token=token, content_type="text/plain", context=context) == 415
            assert _request(url, b"invalid protobuf", token=token, content_type="application/x-protobuf", context=context) == 400
            large = ExportTraceServiceRequest()
            large.CopyFrom(message)
            large.resource_spans[0].scope_spans[0].spans[0].name = "x" * 65537
            assert _request(url, large.SerializeToString(), token=token, content_type="application/x-protobuf", context=context) in (400, 413)
            try:
                plaintext_status = _request(url.replace("https:", "http:"), body, token=token, content_type="application/x-protobuf", context=context)
            except (OSError, URLError):
                pass
            else:
                assert plaintext_status != 200

            unclassified = ExportLogsServiceRequest()
            records = unclassified.resource_logs.add().scope_logs.add().log_records
            for kind, schema in (("unknown", "1"), ("operational", "2")):
                record = records.add()
                for key, value in (("cwl.kind", kind), ("cwl.schema_version", schema)):
                    attribute = record.attributes.add()
                    attribute.key = key
                    attribute.value.string_value = value
            assert _request(
                url.replace("/v1/traces", "/v1/logs"), unclassified.SerializeToString(),
                token=token, content_type="application/x-protobuf", context=context,
            ) == 200
            time.sleep(1.5)
            result = subprocess.run(["docker", "logs", container], capture_output=True, text=True, check=True)
            assert not re.search(
                r'"otelcol.component.id": "debug"[^\n]*"log records": [1-9]',
                result.stdout + result.stderr,
            ), "unclassified log reached the operational backend route"

            runtime = bootstrap(TelemetryConfig(
                service="collector_canary", version="0.1.0", environment="test",
                source_revision="a" * 40, receiver=f"https://127.0.0.1:{port}",
                token=token, ca_file=str(secret_dir / "server.crt"),
                metric_names={"canary_total"}, operation_codes={"canary"},
            ))
            with runtime.tracer.start_as_current_span("canary", {"operation_code": "canary"}):
                runtime.emit(TelemetryEvent(
                    name="canary.completed", severity="INFO", classification="internal",
                    purpose_code="operations", kind="operational",
                    attributes={"operation_code": "canary"},
                ))
                runtime.emit(TelemetryEvent(
                    name="authentication.denied", severity="WARN", classification="internal",
                    purpose_code="security_investigation", kind="security",
                    attributes={"operation_code": "canary", "tenant_ref": "canary_tenant", "event_id": "a" * 32},
                ))
                runtime.meter.counter("canary_total").add(1, {"operation_code": "canary"})
            runtime.shutdown()
            for _ in range(30):
                result = subprocess.run(["docker", "logs", container], capture_output=True, text=True, check=True)
                logs = (result.stdout + result.stderr).replace(token, "<redacted>")
                trace_count = sum(int(count) for count in re.findall(
                    r'"otelcol.signal": "traces"[^\n]*"spans": (\d+)', logs,
                ))
                if (trace_count >= 2
                        and re.search(r'"otelcol.component.id": "debug"[^\n]*"log records": 1', logs)
                        and re.search(r'"otelcol.component.id": "debug/security"[^\n]*"log records": 1', logs)
                        and '"data points": 1' in logs):
                    break
                time.sleep(0.1)
            else:
                pytest.fail(f"SDK signals not observed at Collector: {logs[-1200:]}")
        finally:
            subprocess.run(["docker", "stop", container], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(["docker", "rm", container], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


@pytest.mark.collector
def test_production_collector_requires_persistent_storage_and_validates() -> None:
    """The pinned Collector accepts the operational/security routing template."""
    volume = f"cwl-otel-validate-{uuid.uuid4().hex}"
    container = _run(
        "docker", "create", "-v", f"{volume}:/var/lib/otelcol",
        "-e", "CWL_BACKEND_OTLP_URL=https://backend.example",
        "-e", "CWL_SECURITY_CONSUMER_OTLP_URL=https://security.example",
        IMAGE, "validate", "--config=/config.yaml",
    )
    try:
        _run("docker", "cp", str(PRODUCTION_CONFIG), f"{container}:/config.yaml")
        result = subprocess.run(["docker", "start", "-a", container], capture_output=True, text=True, check=False)
        exit_code = _run("docker", "inspect", container, "--format", "{{.State.ExitCode}}")
        assert exit_code == "0", (result.stdout + result.stderr)[-1200:]
    finally:
        subprocess.run(["docker", "rm", "-f", container], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["docker", "volume", "rm", volume], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


@pytest.mark.collector
def test_security_queue_survives_collector_and_consumer_outage() -> None:
    """A security event crosses the real durable route after both processes restart."""
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        secrets = root / "secrets"
        secrets.mkdir()
        token = "synthetic-ingress-token-12345"
        consumer_token = "synthetic-consumer-token-12345"
        for name, value in (
            ("ingress-token", token), ("backend-token", "synthetic-backend-token-12345"),
            ("security-consumer-token", consumer_token),
        ):
            (secrets / name).write_text(value + "\n", encoding="utf-8")
        _run(
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-subj", "/CN=host.docker.internal",
            "-addext", "subjectAltName=DNS:host.docker.internal,IP:127.0.0.1",
            "-keyout", str(secrets / "receiver.key"), "-out", str(secrets / "receiver.crt"),
            "-days", "1",
        )
        os.chmod(secrets / "receiver.key", 0o644)  # synthetic key for non-root Collector
        for name in ("backend-ca.crt", "security-consumer-ca.crt"):
            (secrets / name).write_bytes((secrets / "receiver.crt").read_bytes())

        outbox = root / "security.sqlite"
        receiver = make_security_server(
            ("0.0.0.0", 0), certificate=secrets / "receiver.crt",
            private_key=secrets / "receiver.key", token_file=secrets / "security-consumer-token",
            tenant_ref="canary_tenant", outbox=outbox,
        )
        consumer_port = receiver.server_port
        receiver.server_close()  # first export sees a real unavailable consumer

        volume = f"cwl-otel-recovery-{uuid.uuid4().hex}"
        _run("docker", "volume", "create", volume)
        container = ""
        worker = None
        try:
            _run(
                "docker", "run", "--rm", "-u", "0:0", "-v", f"{volume}:/var/lib/otelcol",
                "--entrypoint", "chown", ALPINE, "10001:10001", "/var/lib/otelcol",
            )
            host_mapping = ["--add-host", "host.docker.internal:host-gateway"] if platform.system() == "Linux" else []
            container = _run(
                "docker", "create", "-p", "127.0.0.1::4318",
                "-v", f"{volume}:/var/lib/otelcol", *host_mapping,
                "-e", "CWL_BACKEND_OTLP_URL=https://backend.invalid",
                "-e", f"CWL_SECURITY_CONSUMER_OTLP_URL=https://host.docker.internal:{consumer_port}",
                IMAGE, "--config=/config.yaml",
            )
            _run("docker", "cp", str(PRODUCTION_CONFIG), f"{container}:/config.yaml")
            _run("docker", "cp", str(secrets), f"{container}:/secrets")
            _run("docker", "start", container)
            port = _run("docker", "port", container, "4318/tcp").rsplit(":", 1)[-1]
            context = ssl.create_default_context(cafile=str(secrets / "receiver.crt"))
            url = f"https://127.0.0.1:{port}/v1/traces"
            for _ in range(100):
                try:
                    if _request(url, ExportTraceServiceRequest().SerializeToString(),
                                token=token, content_type="application/x-protobuf", context=context) == 200:
                        break
                except (OSError, URLError):
                    pass
                time.sleep(0.1)
            else:
                result = subprocess.run(["docker", "logs", container], capture_output=True, text=True, check=False)
                logs = (result.stdout + result.stderr).replace(token, "<redacted>").replace(consumer_token, "<redacted>")
                pytest.fail(f"production Collector did not start: {logs[-1200:]}")

            runtime = bootstrap(TelemetryConfig(
                service="canary", version="0.1.0", environment="test",
                source_revision="a" * 40, receiver=f"https://127.0.0.1:{port}",
                token=token, ca_file=str(secrets / "receiver.crt"),
            ))
            runtime.emit(TelemetryEvent(
                name="authentication.denied", severity="WARN", classification="internal",
                purpose_code="security_investigation", kind="security",
                attributes={"tenant_ref": "canary_tenant", "event_id": "d" * 32,
                            "operation_code": "login"},
            ))
            runtime.shutdown()
            time.sleep(2)
            _run("docker", "stop", container)
            _run("docker", "start", container)

            receiver = make_security_server(
                ("0.0.0.0", consumer_port), certificate=secrets / "receiver.crt",
                private_key=secrets / "receiver.key", token_file=secrets / "security-consumer-token",
                tenant_ref="canary_tenant", outbox=outbox,
            )
            worker = threading.Thread(target=receiver.serve_forever, daemon=True)
            worker.start()
            for _ in range(150):
                with sqlite3.connect(outbox) as database:
                    rows = pending_security_events(database)
                if [row["event_id"] for row in rows] == ["d" * 32]:
                    break
                time.sleep(0.2)
            else:
                result = subprocess.run(["docker", "logs", container], capture_output=True, text=True, check=False)
                logs = (result.stdout + result.stderr).replace(token, "<redacted>").replace(consumer_token, "<redacted>")
                security_logs = "\n".join(line for line in logs.splitlines() if "otlphttp/security" in line)
                pytest.fail(f"persistent Collector queue did not deliver after recovery: {security_logs[-3000:]}")
        finally:
            if worker is not None:
                receiver.shutdown()
                receiver.server_close()
                worker.join(timeout=5)
            if container:
                subprocess.run(["docker", "rm", "-f", container], check=False,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(["docker", "volume", "rm", volume], check=False,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
