"""Stage 13 slice 13.3: honeytoken registry CSV exporter."""

from __future__ import annotations

import csv
import io
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from anglerfish.dashboard.exporters import (
    HONEYTOKEN_REPORT_COLUMNS,
    build_honeytoken_report_rows,
)
from anglerfish.honeytokens.schema import Honeytoken

_CREATED = datetime(2026, 5, 28, 12, 0, tzinfo=UTC)


def _token(token_id: str, *, payload: str = "SECRETblock") -> Honeytoken:
    return Honeytoken(
        id=token_id,
        kind="aws",
        payload=payload,
        callback_url=f"https://cb.example/{token_id}",
        placed_at="/root/.aws/credentials",
        source_ip="203.0.113.7",
        session_id=uuid4(),
        created_at=_CREATED,
    )


def _rows_to_dicts(
    tokens: list[Honeytoken], callbacks: list[dict[str, Any]]
) -> list[dict[str, str]]:
    raw = b"".join(build_honeytoken_report_rows(tokens, callbacks)).decode("utf-8")
    return list(csv.DictReader(io.StringIO(raw)))


def test_header_is_first_row() -> None:
    raw = b"".join(build_honeytoken_report_rows([], [])).decode("utf-8")
    first = raw.splitlines()[0]
    assert first.split(",") == HONEYTOKEN_REPORT_COLUMNS


def test_one_row_per_token_with_payload() -> None:
    tokens = [_token("MFRGGZDFMZTWQ2LK"), _token("NBSWY3DPEHPK3PXP", payload="OTHERsecret")]
    rows = _rows_to_dicts(tokens, [])
    assert len(rows) == 2
    # The operator-only report deliberately carries the secret payload.
    assert rows[0]["payload"] == "SECRETblock"
    assert rows[1]["payload"] == "OTHERsecret"


def test_token_without_callback_is_not_fired() -> None:
    rows = _rows_to_dicts([_token("MFRGGZDFMZTWQ2LK")], [])
    assert rows[0]["fired"] == "false"
    assert rows[0]["callback_count"] == "0"
    assert rows[0]["last_callback_ts"] == ""
    assert rows[0]["last_callback_source_ip"] == ""


def test_callback_count_and_most_recent_hit() -> None:
    tid = "MFRGGZDFMZTWQ2LK"
    # iter_events_in_range yields newest-first, so the first event is the latest hit.
    callbacks = [
        {"token_id": tid, "ts": "2026-05-29T10:00:00Z", "callback_source_ip": "198.51.100.9"},
        {"token_id": tid, "ts": "2026-05-28T09:00:00Z", "callback_source_ip": "198.51.100.1"},
    ]
    rows = _rows_to_dicts([_token(tid)], callbacks)
    assert rows[0]["fired"] == "true"
    assert rows[0]["callback_count"] == "2"
    assert rows[0]["last_callback_ts"] == "2026-05-29T10:00:00Z"
    assert rows[0]["last_callback_source_ip"] == "198.51.100.9"


def test_callbacks_grouped_per_token() -> None:
    a, b = "MFRGGZDFMZTWQ2LK", "NBSWY3DPEHPK3PXP"
    callbacks = [
        {"token_id": a, "ts": "2026-05-29T10:00:00Z", "callback_source_ip": "198.51.100.9"},
        {"token_id": b, "ts": "2026-05-29T09:00:00Z", "callback_source_ip": "198.51.100.2"},
        {"token_id": a, "ts": "2026-05-28T08:00:00Z", "callback_source_ip": "198.51.100.1"},
    ]
    rows = {r["id"]: r for r in _rows_to_dicts([_token(a), _token(b)], callbacks)}
    assert rows[a]["callback_count"] == "2"
    assert rows[b]["callback_count"] == "1"


def test_callback_without_token_id_is_skipped() -> None:
    callbacks = [{"token_id": None, "ts": "2026-05-29T10:00:00Z", "callback_source_ip": "x"}]
    rows = _rows_to_dicts([_token("MFRGGZDFMZTWQ2LK")], callbacks)
    assert rows[0]["fired"] == "false"
