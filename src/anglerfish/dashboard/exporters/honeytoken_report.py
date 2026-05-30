"""Honeytoken registry CSV exporter (Stage 13 slice 13.3).

Pays off the long-standing ``honeytoken_report`` export stub
(``{"available": False, "stage": 11}``). Emits one CSV row per
registered honeytoken, joined against the ``bridge.honeytoken_callback``
audit events so each row carries its callback count and most-recent hit.

Unlike the STIX 2.1 and MISP exporters (slice 13.4), which travel to
shared intel feeds and therefore emit identifiers and callback URLs
only, this report is the operator-only canonical record and DOES carry
the secret ``payload`` (the fake AWS credential block / SSH private key
the attacker exfiltrates). THREAT_MODEL.md reserves the full payload for
exactly this path: it is an authenticated file download, never pushed to
a third party. The route is auth-gated and the filename marks it
operator-only.
"""

from __future__ import annotations

import csv
import io
from collections.abc import Iterable, Iterator
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from anglerfish.honeytokens.schema import Honeytoken

__all__ = ["HONEYTOKEN_REPORT_COLUMNS", "build_honeytoken_report_rows"]


HONEYTOKEN_REPORT_COLUMNS = [
    "id",
    "kind",
    "placed_at",
    "source_ip",
    "session_id",
    "created_at",
    "callback_url",
    "payload",
    "fired",
    "callback_count",
    "last_callback_ts",
    "last_callback_source_ip",
]


def build_honeytoken_report_rows(
    tokens: list[Honeytoken],
    callbacks: list[dict[str, Any]],
) -> Iterator[bytes]:
    """Yield the honeytoken report as UTF-8 CSV byte rows, header first.

    ``callbacks`` are the ``bridge.honeytoken_callback`` audit events in
    newest-first order (the order ``iter_events_in_range`` yields). For
    each token the first callback seen is therefore its most recent, so
    ``last_callback_*`` is read from the first event per ``token_id`` and
    the count is the total. Tokens with no callback emit ``fired=false``
    and empty callback columns.

    Pure transform: no I/O, no store or audit access. The route gathers
    the registry and the callback events and hands them in.
    """
    aggregates = _aggregate_callbacks(callbacks)
    yield _csv_row(HONEYTOKEN_REPORT_COLUMNS)
    for token in tokens:
        agg = aggregates.get(token.id)
        count = agg["count"] if agg else 0
        yield _csv_row(
            [
                token.id,
                token.kind,
                token.placed_at,
                token.source_ip,
                str(token.session_id) if token.session_id else None,
                token.created_at.isoformat(),
                token.callback_url,
                token.payload,
                "true" if count else "false",
                count,
                agg["last_ts"] if agg else None,
                agg["last_source_ip"] if agg else None,
            ],
        )


def _aggregate_callbacks(callbacks: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Group newest-first callback events by ``token_id``.

    Returns ``{token_id: {"count": int, "last_ts": str|None,
    "last_source_ip": str|None}}``. The first event seen per token is the
    most recent (input is newest-first), so its timestamp and source IP
    are the "last callback" for that token.
    """
    aggregates: dict[str, dict[str, Any]] = {}
    for event in callbacks:
        token_id = event.get("token_id")
        if not token_id:
            continue
        agg = aggregates.get(token_id)
        if agg is None:
            aggregates[token_id] = {
                "count": 1,
                "last_ts": event.get("ts"),
                "last_source_ip": event.get("callback_source_ip"),
            }
        else:
            agg["count"] += 1
    return aggregates


def _csv_row(cells: Iterable[object]) -> bytes:
    """Render one CSV row to bytes via the stdlib writer (handles quoting)."""
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\n")
    writer.writerow(["" if c is None else str(c) for c in cells])
    return buf.getvalue().encode("utf-8")
