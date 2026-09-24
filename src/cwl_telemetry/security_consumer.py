"""Single-tenant HTTPS OTLP receiver for normalized security-event outbox."""

from __future__ import annotations

import argparse
import hmac
import os
import re
import sqlite3
import ssl
import stat
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from .security import decode_security_export


def make_security_server(
    address: tuple[str, int], *, certificate: Path, private_key: Path,
    token_file: Path, tenant_ref: str, outbox: Path, max_pending: int = 100_000,
) -> HTTPServer:
    """Bind one authenticated tenant to a durable OTLP security receiver."""
    if re.fullmatch(r"[A-Za-z0-9_-]{1,64}", tenant_ref) is None:
        raise ValueError("invalid tenant reference")
    token = token_file.read_text(encoding="utf-8").rstrip("\n")
    if not 16 <= len(token) <= 4096 or any(character.isspace() for character in token):
        raise ValueError("invalid receiver token")
    if not outbox.parent.is_dir():
        raise ValueError("outbox directory must exist")
    if type(max_pending) is not int or not 1 <= max_pending <= 1_000_000:
        raise ValueError("invalid outbox capacity")
    try:
        descriptor = os.open(outbox, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError:
        pass
    else:
        os.close(descriptor)
    metadata = outbox.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_mode & 0o077:
        raise ValueError("outbox must be a private regular file")

    class Handler(BaseHTTPRequestHandler):
        """Admit fixed-path OTLP logs without recording request contents."""

        timeout = 5

        def log_message(self, _format: str, *_args: object) -> None:
            """Suppress standard request-path and header logging."""

        def _reply(self, status: int) -> None:
            self.send_response(status)
            self.send_header("Content-Length", "0")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()

        def do_POST(self) -> None:
            """Validate HTTP admission before decoding an OTLP batch."""
            if self.path != "/v1/logs":
                self._reply(404)
                return
            supplied = self.headers.get("Authorization", "")
            if not hmac.compare_digest(supplied, f"Bearer {token}"):
                self._reply(401)
                return
            if self.headers.get("Content-Type") != "application/x-protobuf":
                self._reply(415)
                return
            if self.headers.get("Content-Encoding") not in (None, "identity"):
                self._reply(415)
                return
            if self.headers.get("Transfer-Encoding") is not None:
                self._reply(400)
                return
            try:
                length = int(self.headers.get("Content-Length", ""))
            except ValueError:
                self._reply(411)
                return
            if not 0 < length <= 65_536:
                self._reply(413)
                return
            try:
                payload = self.rfile.read(length)
            except TimeoutError:
                self._reply(408)
                return
            if len(payload) != length:
                self._reply(400)
                return
            try:
                with sqlite3.connect(outbox, timeout=5) as connection:
                    decode_security_export(
                        payload, authenticated_tenant=tenant_ref,
                        replay_db=connection, max_pending=max_pending,
                    )
            except ValueError as error:
                self._reply(503 if str(error) == "security outbox full" else 400)
                return
            except sqlite3.Error:
                self._reply(503)
                return
            self._reply(200)

    # ponytail: one request at a time keeps SQLite write ordering simple; use
    # per-tenant replicas when measured Collector load exceeds this receiver.
    server = HTTPServer(address, Handler)
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(str(certificate), str(private_key))
        server.socket = context.wrap_socket(
            server.socket, server_side=True, do_handshake_on_connect=False,
        )
    except Exception:
        server.server_close()
        raise
    return server


def main() -> None:
    """Run the receiver with operator-mounted credentials and outbox storage."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--listen", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=4319)
    parser.add_argument("--certificate", type=Path, required=True)
    parser.add_argument("--private-key", type=Path, required=True)
    parser.add_argument("--token-file", type=Path, required=True)
    parser.add_argument("--tenant-ref", required=True)
    parser.add_argument("--outbox", type=Path, required=True)
    parser.add_argument("--max-pending", type=int, default=100_000)
    args = parser.parse_args()
    server = make_security_server(
        (args.listen, args.port), certificate=args.certificate,
        private_key=args.private_key, token_file=args.token_file,
        tenant_ref=args.tenant_ref, outbox=args.outbox,
        max_pending=args.max_pending,
    )
    try:
        server.serve_forever()
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
