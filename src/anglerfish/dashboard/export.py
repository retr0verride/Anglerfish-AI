"""Date-range exporters for session snapshots and audit log entries.

Two endpoints sit on top of these helpers:

* ``GET /api/export/sessions`` returns persisted session snapshots
  within the supplied range, in JSON or CSV.
* ``GET /api/export/audit`` returns audit log entries within the
  range, JSON only (audit events have variable fields per
  ``event_type`` so flattening to CSV would be lossy).

Both endpoints enforce a 7-day maximum per request. The cap exists
to bound response size; the session store could serve longer
windows, but the SPA renders the response in one go and a multi-
month dump would lock up the browser tab.

The CSV path uses a streaming response so a maxed-out 7-day request
on a busy honeypot does not materialise the full payload in memory.
Sessions come from :class:`anglerfish.sessions.SessionStore` via
``DashboardState.store.get_sessions_in_range`` so the export sees
historical sessions, not just those still resident in memory.
"""

from __future__ import annotations

import csv
import io
from collections.abc import AsyncIterator, Iterable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any

from anglerfish.dashboard.audit_reader import iter_events_in_range

if TYPE_CHECKING:
    from anglerfish.dashboard.state import DashboardState

__all__ = [
    "EXPORT_STUBS",
    "MAX_EXPORT_WINDOW_DAYS",
    "ExportRangeError",
    "audit_export_payload",
    "intent_export_payload",
    "parse_range",
    "session_csv_rows",
    "session_export_payload",
]


MAX_EXPORT_WINDOW_DAYS = 7

# Export formats and their availability, returned in every export
# response so the SPA can enable or grey-disable buttons. Stage 13
# slice 13.4 made the STIX 2.1 and MISP exporters live; honeytoken_report
# is still a stub until slice 13.3.
EXPORT_STUBS: dict[str, dict[str, Any]] = {
    "stix2": {"available": True, "stage": 13},
    "misp_json": {"available": True, "stage": 13},
    "honeytoken_report": {"available": False, "stage": 11},
}


class ExportRangeError(ValueError):
    """Raised when the requested date range is invalid (bad ISO, end<start, span>cap)."""


def parse_range(
    *,
    from_: str | None,
    to_: str | None,
    now: datetime | None = None,
) -> tuple[datetime, datetime]:
    """Parse ISO-8601 from/to into UTC datetimes; apply defaults + cap.

    Defaults: ``to`` to now; ``from`` to now-24h. Both bounds are
    inclusive; ``end < start`` is rejected, as is any span longer
    than :data:`MAX_EXPORT_WINDOW_DAYS`.

    All returned datetimes are timezone-aware UTC. Naive inputs are
    treated as UTC (consistent with the rest of the audit-log
    timestamps).
    """
    current = now or datetime.now(tz=UTC)
    end = _parse_iso(to_) if to_ else current
    start = _parse_iso(from_) if from_ else (end - timedelta(hours=24))
    if end < start:
        raise ExportRangeError("export range: 'to' must be >= 'from'")
    span = end - start
    if span > timedelta(days=MAX_EXPORT_WINDOW_DAYS):
        raise ExportRangeError(
            f"export range: span exceeds {MAX_EXPORT_WINDOW_DAYS}-day cap "
            f"({span.days} days requested). Narrow the range.",
        )
    return start, end


async def session_export_payload(
    dashboard_state: DashboardState,
    *,
    start: datetime,
    end: datetime,
) -> dict[str, Any]:
    """Build the JSON response for a session export."""
    items = await _sessions_in_range(dashboard_state, start=start, end=end)
    return {
        "available": True,
        "format": "json",
        "from": start.isoformat(),
        "to": end.isoformat(),
        "count": len(items),
        "items": items,
        "stubs": EXPORT_STUBS,
    }


async def session_csv_rows(
    dashboard_state: DashboardState,
    *,
    start: datetime,
    end: datetime,
) -> AsyncIterator[bytes]:
    """Yield CSV rows as UTF-8 bytes, header first.

    Used by a Starlette ``StreamingResponse`` so a 7-day worst-case
    export does not materialise the full payload in process memory.
    """
    items = await _sessions_in_range(dashboard_state, start=start, end=end)
    columns = [
        "session_id",
        "source_ip",
        "username",
        "started_at",
        "ended_at",
        "command_count",
        "fake_hostname",
        "fake_username",
    ]
    yield _csv_row(columns)
    for item in items:
        yield _csv_row([_csv_value(item.get(c)) for c in columns])


async def intent_export_payload(
    dashboard_state: DashboardState,
    *,
    start: datetime,
    end: datetime,
) -> dict[str, Any]:
    """Build the JSON response for an intent-summary export.

    Returns every :class:`IntentSummary` whose ``extracted_at``
    falls inside ``[start, end]``. Newest-first (matches the
    SessionStore query order); operators reverse client-side if
    they want chronological order.
    """
    items = await dashboard_state.get_intents_in_range(start=start, end=end)
    return {
        "available": True,
        "format": "json",
        "from": start.isoformat(),
        "to": end.isoformat(),
        "count": len(items),
        "items": [item.model_dump(mode="json") for item in items],
        "stubs": EXPORT_STUBS,
    }


def audit_export_payload(
    audit_path: Path,
    *,
    start: datetime,
    end: datetime,
) -> dict[str, Any]:
    """Build the JSON response for an audit-log export.

    Reads the audit JSONL in newest-first order, filters to the
    range, then reverses so the returned items are oldest-first
    (the natural reading order for chronological review).
    """
    raw = list(iter_events_in_range(audit_path, start=start, end=end))
    raw.reverse()
    return {
        "available": True,
        "format": "json",
        "from": start.isoformat(),
        "to": end.isoformat(),
        "count": len(raw),
        "items": raw,
        "stubs": EXPORT_STUBS,
    }


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------


def _parse_iso(value: str) -> datetime:
    """Parse an ISO-8601 string into a UTC datetime, raising ExportRangeError."""
    try:
        # fromisoformat handles "Z" only on 3.11+; defensive replace
        # keeps older lock-files compatible without bumping the floor.
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ExportRangeError(f"export range: invalid ISO timestamp {value!r}") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


async def _sessions_in_range(
    dashboard_state: DashboardState,
    *,
    start: datetime,
    end: datetime,
) -> list[dict[str, Any]]:
    """Query the session store for sessions started in [start, end]."""
    sessions = await dashboard_state.store.get_sessions_in_range(
        start=start,
        end=end,
    )
    return [session.model_dump(mode="json") for session in sessions]


def _csv_row(cells: Iterable[object]) -> bytes:
    """Render one CSV row to bytes via the stdlib writer (handles quoting)."""
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\n")
    writer.writerow([_csv_value(c) for c in cells])
    return buf.getvalue().encode("utf-8")


def _csv_value(value: object) -> str:
    """Coerce a session-payload value into a CSV-safe string."""
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    return str(value)
