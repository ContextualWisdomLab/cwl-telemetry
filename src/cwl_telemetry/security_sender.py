"""One-batch HTTPS handoff from the normalized security outbox to a SIEM gateway."""

from __future__ import annotations

import argparse
import json
import re
import sqlite3
import ssl
import stat
import sys
from pathlib import Path
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, HTTPSHandler, Request, build_opener

from .security import mark_security_delivered, pending_security_events


class _NoRedirect(HTTPRedirectHandler):
    """Never forward a bearer credential to a redirected destination."""

    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


def _ack_fields(pairs: list[tuple[str, object]]) -> dict[str, object]:
    fields = dict(pairs)
    if len(fields) != len(pairs):
        raise ValueError("duplicate SIEM acknowledgement field")
    return fields


def _gateway_url(origin: str) -> str:
    if not isinstance(origin, str) or any(ord(char) <= 32 for char in origin):
        raise ValueError("invalid SIEM gateway origin")
    parsed = urlsplit(origin)
    try:
        valid_port = parsed.port is None or 1 <= parsed.port <= 65535
    except ValueError:
        valid_port = False
    if (parsed.scheme != "https" or not parsed.hostname or not valid_port
            or parsed.username or parsed.password or parsed.query or parsed.fragment
            or parsed.path not in ("", "/")):
        raise ValueError("invalid SIEM gateway origin")
    return origin.rstrip("/") + "/v1/security-events"


def deliver_pending(
    outbox: Path, *, gateway: str, token: str, ca_file: Path | None = None,
    limit: int = 100,
) -> int:
    """Mark each record only after the gateway acknowledges its exact event ID."""
    target = _gateway_url(gateway)
    if not isinstance(token, str) or not 16 <= len(token) <= 4096 or any(char.isspace() for char in token):
        raise ValueError("invalid SIEM gateway token")
    if type(limit) is not int or not 1 <= limit <= 1000:
        raise ValueError("invalid delivery batch size")
    metadata = outbox.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_mode & 0o077:
        raise ValueError("outbox must be a private regular file")
    context = ssl.create_default_context(cafile=str(ca_file) if ca_file else None)
    opener = build_opener(_NoRedirect(), HTTPSHandler(context=context))
    with sqlite3.connect(outbox, timeout=5) as connection:
        if connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'security_event_outbox'"
        ).fetchone() is None:
            raise ValueError("security outbox is missing")
        delivered = 0
        for event in pending_security_events(connection, limit=limit):
            event_id = event["event_id"]
            if re.fullmatch(r"[0-9a-f]{32}", event_id) is None:
                raise ValueError("invalid stored security event ID")
            request = Request(
                target, data=json.dumps(event, sort_keys=True).encode("utf-8"),
                headers={
                    "Authorization": f"Bearer {token}",
                    "Content-Type": "application/json",
                    "Idempotency-Key": event_id,
                }, method="POST",
            )
            with opener.open(request, timeout=5) as response:
                body = response.read(1025)
                if (response.status != 200 or response.headers.get("Content-Type") != "application/json"
                        or len(body) > 1024):
                    raise ValueError("invalid SIEM acknowledgement")
            try:
                acknowledgement = json.loads(body, object_pairs_hook=_ack_fields)
            except (UnicodeDecodeError, json.JSONDecodeError) as error:
                raise ValueError("invalid SIEM acknowledgement") from error
            if (not isinstance(acknowledgement, dict)
                    or acknowledgement.keys() != {"accepted", "event_id"}
                    or acknowledgement["accepted"] is not True
                    or acknowledgement["event_id"] != event_id):
                raise ValueError("invalid SIEM acknowledgement")
            mark_security_delivered(connection, event_id)
            delivered += 1
    return delivered


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--outbox", required=True, type=Path)
    parser.add_argument("--gateway", required=True, help="approved HTTPS gateway origin")
    parser.add_argument("--ca-file", type=Path)
    parser.add_argument("--limit", type=int, default=100)
    args = parser.parse_args()
    token = sys.stdin.readline(4097).rstrip("\n")
    try:
        count = deliver_pending(
            args.outbox, gateway=args.gateway, token=token,
            ca_file=args.ca_file, limit=args.limit,
        )
    except Exception:
        raise SystemExit("Security delivery unavailable; unacknowledged events remain pending") from None
    print(f"Acknowledged security events: {count}")


if __name__ == "__main__":
    main()
