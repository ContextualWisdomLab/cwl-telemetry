"""Real Collector admission canary with synthetic local-only telemetry."""

from __future__ import annotations

import os
import re
import ssl
import subprocess
import tempfile
import time
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

import pytest
from opentelemetry.proto.collector.trace.v1.trace_service_pb2 import ExportTraceServiceRequest
from cwl_telemetry import TelemetryConfig, TelemetryEvent, bootstrap


IMAGE = "otel/opentelemetry-collector-contrib@sha256:fd328de2552466ad78385e1b1289c3f2402b1c45f265b252aab1955b42845ac1"
CONFIG = Path(__file__).parents[1] / "collector" / "canary.yaml"


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
                    attributes={"operation_code": "canary"},
                ))
                runtime.meter.counter("canary_total").add(1, {"operation_code": "canary"})
            runtime.shutdown()
            for _ in range(30):
                result = subprocess.run(["docker", "logs", container], capture_output=True, text=True, check=True)
                logs = (result.stdout + result.stderr).replace(token, "<redacted>")
                if ('"resource spans": 2' in logs and '"log records": 2' in logs
                        and re.search(r'"otelcol.component.id": "debug/security"[^\n]*"log records": 1', logs)
                        and '"data points": 1' in logs):
                    break
                time.sleep(0.1)
            else:
                pytest.fail(f"SDK signals not observed at Collector: {logs[-1200:]}")
        finally:
            subprocess.run(["docker", "stop", container], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(["docker", "rm", container], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
