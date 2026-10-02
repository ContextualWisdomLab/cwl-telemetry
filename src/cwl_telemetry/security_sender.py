"""One-batch HTTPS handoff from the normalized security outbox to a SIEM gateway."""

from __future__ import annotations

import argparse
from contextlib import closing
import json
import re
import sqlite3
import ssl
import stat
import sys
import time
from pathlib import Path
from typing import NamedTuple
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, HTTPSHandler, Request, build_opener

from . import _valid_bearer_token
from .security import (
    _expire_delivered, _quarantine_security_event, mark_security_delivered,
    pending_security_events,
)


_PERMANENT_EVENT_REJECTION_CODES = frozenset({400, 422})


class DeliverySummary(NamedTuple):
    """Count acknowledged and quarantined rows handled by one sender run."""

    delivered: int
    quarantined: int


class _NoRedirect(HTTPRedirectHandler):
    """Never forward a bearer credential to a redirected destination."""

    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


def _ack_fields(pairs: list[tuple[str, object]]) -> dict[str, object]:
    fields = dict(pairs)
    if len(fields) != len(pairs):
        raise ValueError("duplicate SIEM acknowledgement field")
    return fields


def _gateway_document(response) -> dict[str, object] | None:
    """Decode one small, duplicate-free JSON gateway response."""
    body = response.read(1025)
    if response.headers.get_all("Content-Type") != ["application/json"] or len(body) > 1024:
        return None
    try:
        document = json.loads(body, object_pairs_hook=_ack_fields)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        return None
    return document if isinstance(document, dict) else None


def _gateway_url(origin: str) -> str:
    if not isinstance(origin, str) or any(ord(char) <= 32 for char in origin):
        raise ValueError("invalid SIEM gateway origin")
    parsed = urlsplit(origin)
    try:
        valid_port = parsed.port is None or 1 <= parsed.port <= 65535
    except ValueError:
        valid_port = False
    if (parsed.scheme != "https" or not parsed.hostname or not valid_port
            or parsed.username is not None or parsed.password is not None
            or parsed.query or parsed.fragment
            or parsed.path not in ("", "/")):
        raise ValueError("invalid SIEM gateway origin")
    return origin.rstrip("/") + "/v1/security-events"


def deliver_pending(
    outbox: Path, *, gateway: str, token: str, ca_file: Path | None = None,
    limit: int = 100,
) -> DeliverySummary:
    """Deliver pending rows while isolating authenticated permanent rejections."""
    target = _gateway_url(gateway)
    if not _valid_bearer_token(token):
        raise ValueError("invalid SIEM gateway token")
    if type(limit) is not int or not 1 <= limit <= 1000:
        raise ValueError("invalid delivery batch size")
    metadata = outbox.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_mode & 0o077:
        raise ValueError("outbox must be a private regular file")
    context = ssl.create_default_context(cafile=str(ca_file) if ca_file else None)
    opener = build_opener(_NoRedirect(), HTTPSHandler(context=context))
    with closing(sqlite3.connect(outbox, timeout=5)) as connection, connection:
        if connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'security_event_outbox'"
        ).fetchone() is None:
            raise ValueError("security outbox is missing")
        _expire_delivered(connection, time.time_ns())
        connection.commit()
        delivered = 0
        quarantined = 0
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
            try:
                with opener.open(request, timeout=5) as response:
                    acknowledgement = _gateway_document(response)
                    if response.status != 200 or acknowledgement is None:
                        raise ValueError("invalid SIEM acknowledgement")
            except HTTPError as error:
                status_code = error.code
                rejection = _gateway_document(error)
                error.close()
                if (status_code in _PERMANENT_EVENT_REJECTION_CODES
                        and rejection is not None
                        and rejection.keys() == {"rejected", "event_id"}
                        and rejection["rejected"] is True
                        and rejection["event_id"] == event_id):
                    _quarantine_security_event(connection, event_id)
                    quarantined += 1
                    continue
                raise
            if (acknowledgement.keys() != {"accepted", "event_id"}
                    or acknowledgement["accepted"] is not True
                    or acknowledgement["event_id"] != event_id):
                raise ValueError("invalid SIEM acknowledgement")
            mark_security_delivered(connection, event_id)
            delivered += 1
    return DeliverySummary(delivered=delivered, quarantined=quarantined)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--outbox", required=True, type=Path)
    parser.add_argument("--gateway", required=True, help="approved HTTPS gateway origin")
    parser.add_argument("--ca-file", type=Path)
    parser.add_argument("--limit", type=int, default=100)
    args = parser.parse_args()
    token = sys.stdin.readline(4097).rstrip("\n")
    try:
        summary = deliver_pending(
            args.outbox, gateway=args.gateway, token=token,
            ca_file=args.ca_file, limit=args.limit,
        )
    except Exception:
        raise SystemExit("Security delivery unavailable; unacknowledged events remain pending") from None
    print(f"Acknowledged security events: {summary.delivered}")
    print(f"Quarantined security events: {summary.quarantined}")
    if summary.quarantined:
        raise SystemExit(2)


if __name__ == "__main__":
    main()
