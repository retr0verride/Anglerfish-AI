"""Audit-log-backed alerts feed for the dashboard.

The alerts panel exposes ``GET /api/alerts`` with newest-first
pagination over the recognised alert event kinds. Future-stage
alert kinds (honeytoken callback hits, behavioural cluster
matches, intent summary alerts) are stubbed with
``available: false`` so the SPA can render them grey-disabled
without round-tripping.

Cursors are opaque strings of the form ``"<ts_ms>-<offset>"`` where
``ts_ms`` is the millisecond Unix timestamp of the last event
returned and ``offset`` is the per-millisecond tiebreaker (events
within the same millisecond keep their JSONL order). The cursor
contract is exposed but not parsed by callers; round-trip via
``next_cursor`` is the only supported usage.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from anglerfish.dashboard.audit_reader import iter_events, parse_event_timestamp

__all__ = [
    "ALERT_KINDS",
    "ALERT_STUBS",
    "list_alerts",
]


# Event types we surface as alerts, mapped to the operator-facing
# "kind" label used in the response. Adding a new kind requires both
# the event type (matched against audit log) and the human label.
_ALERT_EVENT_TYPES: dict[str, str] = {
    "bridge.defense_fired": "defense_fired",
    "bridge.defense_scan_truncated": "defense_scan_truncated",
    "lure.subsystem_refused": "subsystem_refused",
    "threat.alert_fired": "high_severity_session",
    # Persistence-attempt event ships under Stage 10; the type name
    # is reserved here so the alerts endpoint surfaces it the moment
    # the bridge starts emitting it, with no dashboard change.
    "bridge.persistence_attempt": "persistence_attempt",
}

ALERT_KINDS: frozenset[str] = frozenset(_ALERT_EVENT_TYPES.values())

# Future-stage alert categories. The endpoint always returns this
# block so the SPA can grey-disable buttons without round-tripping
# to /api/stage/*.
ALERT_STUBS: dict[str, dict[str, Any]] = {
    "honeytoken_callback_hits": {"available": False, "stage": 11},
    "behavioral_cluster_matches": {"available": False, "stage": 8},
    "intent_summary_alerts": {"available": False, "stage": 7},
}


def list_alerts(
    audit_path: Path,
    *,
    limit: int = 50,
    cursor: str | None = None,
    kind: str | None = None,
) -> dict[str, Any]:
    """Return the next page of alerts plus the future-stage stub list.

    ``cursor`` is the opaque value returned as ``next_cursor`` in a
    previous call. ``kind`` filters to a single recognised label;
    unknown kinds yield an empty page rather than an error (the SPA
    may chip-filter on a kind that has not yet been seen).
    """
    if kind is not None and kind not in ALERT_KINDS:
        return _empty_page()

    cursor_bound = _parse_cursor(cursor)
    items: list[dict[str, Any]] = []
    last_ts_ms: int | None = None
    same_ms_offset = 0

    for event in iter_events(audit_path):
        event_type = event.get("event_type")
        label = _ALERT_EVENT_TYPES.get(str(event_type))
        if label is None:
            continue
        if kind is not None and label != kind:
            continue
        ts = parse_event_timestamp(event)
        if ts is None:
            continue
        ts_ms = int(ts.timestamp() * 1000)

        # Cursor compares as (ts_ms, offset). We track a per-ms
        # offset so events that share a millisecond paginate
        # deterministically.
        if ts_ms == last_ts_ms:
            same_ms_offset += 1
        else:
            same_ms_offset = 0
            last_ts_ms = ts_ms

        if cursor_bound is not None:
            bound_ms, bound_offset = cursor_bound
            if (ts_ms, same_ms_offset) >= (bound_ms, bound_offset):
                continue

        items.append(_render_alert(event, label, ts_ms, same_ms_offset))
        if len(items) >= limit:
            break

    next_cursor: str | None = None
    if len(items) >= limit:
        tail = items[-1]
        next_cursor = f"{tail['_cursor_ts_ms']}-{tail['_cursor_offset']}"
    for item in items:
        item.pop("_cursor_ts_ms", None)
        item.pop("_cursor_offset", None)

    return {
        "items": items,
        "next_cursor": next_cursor,
        "stubs": ALERT_STUBS,
    }


def _render_alert(
    event: dict[str, Any],
    label: str,
    ts_ms: int,
    offset: int,
) -> dict[str, Any]:
    """Project an audit event into the operator-facing alert shape.

    The cursor fields are stripped before the page is returned;
    they're carried on the item only so the loop above can derive
    ``next_cursor`` without re-parsing.
    """
    detail = _summarise_event(event, label)
    return {
        "id": f"{ts_ms}-{offset}",
        "ts": event.get("ts"),
        "kind": label,
        "available": True,
        "session_id": event.get("session_id"),
        "source_ip": event.get("attacker_ip") or event.get("source_ip"),
        "detail": detail,
        "_cursor_ts_ms": ts_ms,
        "_cursor_offset": offset,
    }


def _summarise_event(event: dict[str, Any], label: str) -> str:
    """One-line detail string per alert kind."""
    if label == "defense_fired":
        detector = event.get("detector", "unknown")
        score = event.get("score")
        return f"{detector} (score={score})" if score is not None else str(detector)
    if label == "defense_scan_truncated":
        kind = event.get("kind", "unknown")
        scan_cap = event.get("scan_max_chars")
        input_len = event.get("input_length")
        return f"{kind} scan truncated: input={input_len} chars, cap={scan_cap} chars"
    if label == "subsystem_refused":
        kind = event.get("kind", "unknown")
        return f"refused {kind}"
    if label == "high_severity_session":
        score = event.get("score")
        return f"high-severity session (score={score})"
    if label == "persistence_attempt":
        return str(event.get("detail") or "persistence attempted")
    return "alert"


def _parse_cursor(cursor: str | None) -> tuple[int, int] | None:
    """Parse a ``ts_ms-offset`` cursor; return None for missing or malformed."""
    if not cursor:
        return None
    parts = cursor.split("-", 1)
    if len(parts) != 2:
        return None
    try:
        return int(parts[0]), int(parts[1])
    except ValueError:
        return None


def _empty_page() -> dict[str, Any]:
    """Empty-page response shape; matches the live shape from :func:`list_alerts`."""
    return {
        "items": [],
        "next_cursor": None,
        "stubs": ALERT_STUBS,
    }
