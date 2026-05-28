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

from collections.abc import Callable
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
    # Stage 7: every successful intent extraction surfaces as an
    # alert; operators chip-filter by kind="intent_summary" in the
    # SPA. The previous available:false stub flipped here.
    "bridge.intent_extracted": "intent_summary",
    # Stage 8 slice 5: the tailer emits bridge.cluster_match after
    # persisting an embedding when find_similar returns one or more
    # neighbours above settings.bridge.cluster_similarity_threshold.
    # The previous behavioral_cluster_matches:available=false stub
    # flipped here in the same commit.
    "bridge.cluster_match": "cluster_match",
    # Persistence-attempt event ships under Stage 10; the type name
    # is reserved here so the alerts endpoint surfaces it the moment
    # the bridge starts emitting it, with no dashboard change.
    "bridge.persistence_attempt": "persistence_attempt",
    # Stage 11 slice 11.4: the bundled callback receiver writes
    # bridge.honeytoken_callback into its own audit log; operators
    # ship those lines back into the main audit log via their
    # existing forwarder (rsync, Splunk, syslog). The alerts panel
    # surfaces them the moment they land. The previous
    # honeytoken_callback_hits:available=false stub flipped here in
    # the same commit.
    "bridge.honeytoken_callback": "honeytoken_callback_hit",
    # Stage 12 slice 12.4: counter-deception engagement (threat-driven
    # or operator-pinned) surfaces as an alert. The garble-served +
    # timebomb-applied events are intentionally NOT alerts - they are
    # per-command noise; the once-per-session engagement is the signal.
    "bridge.counter_deception_engaged": "counter_deception_engaged",
}

ALERT_KINDS: frozenset[str] = frozenset(_ALERT_EVENT_TYPES.values())

# Future-stage alert categories. Empty after Stage 11 slice 11.4
# flipped the honeytoken_callback_hits stub live; kept as an
# explicit dict so the response shape is stable across stages (the
# SPA reads `stubs` unconditionally) and future stages can register
# new placeholders without churning the endpoint contract.
ALERT_STUBS: dict[str, dict[str, Any]] = {}


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
    """One-line detail string per alert kind.

    Dispatches to a per-label helper so each branch stays small and
    the registry trivially extends when a new kind ships.
    """
    summariser = _SUMMARISERS.get(label)
    return summariser(event) if summariser is not None else "alert"


def _summarise_defense_fired(event: dict[str, Any]) -> str:
    detector = event.get("detector", "unknown")
    score = event.get("score")
    return f"{detector} (score={score})" if score is not None else str(detector)


def _summarise_defense_scan_truncated(event: dict[str, Any]) -> str:
    kind = event.get("kind", "unknown")
    scan_cap = event.get("scan_max_chars")
    input_len = event.get("input_length")
    return f"{kind} scan truncated: input={input_len} chars, cap={scan_cap} chars"


def _summarise_subsystem_refused(event: dict[str, Any]) -> str:
    kind = event.get("kind", "unknown")
    return f"refused {kind}"


def _summarise_high_severity_session(event: dict[str, Any]) -> str:
    return f"high-severity session (score={event.get('score')})"


def _summarise_persistence_attempt(event: dict[str, Any]) -> str:
    """Render a bridge.persistence_attempt event for the alerts panel.

    Stage 10 emits structured fields (kind / sub_key / payload /
    source); this renderer produces a one-line operator summary
    like ``crontab: 0 * * * * /tmp/.x (regex)`` or
    ``systemctl enabled backdoor.service (llm)``. Falls back to
    the pre-Stage-10 ``detail`` field for any older audit lines
    still in the log so a tailer replay does not produce blank
    rows.
    """
    kind = event.get("kind")
    payload = event.get("payload")
    if not isinstance(kind, str) or not isinstance(payload, str):
        return str(event.get("detail") or "persistence attempted")
    source = event.get("source", "unknown")
    sub_key = event.get("sub_key")
    if kind == "systemctl" and isinstance(sub_key, str):
        body = f"systemctl enabled {sub_key}"
    elif kind == "authorized_keys":
        body = f"authorized_keys += {payload[:80]}"
    else:
        body = f"{kind}: {payload[:120]}"
    return f"{body} ({source})"


def _summarise_intent_summary(event: dict[str, Any]) -> str:
    profile = event.get("actor_profile", "unknown")
    confidence = event.get("confidence", "unknown")
    intent = event.get("intent")
    if isinstance(intent, str) and intent:
        return f"{profile} / {confidence}: {intent}"
    return f"{profile} / {confidence}"


def _summarise_honeytoken_callback(event: dict[str, Any]) -> str:
    """Render a bridge.honeytoken_callback event for the alerts panel.

    The callback receiver emits the event with ``token_id``,
    ``kind`` (``aws`` / ``ssh_key``), ``registered_source_ip``
    (the IP that exfiltrated the bait), ``callback_source_ip``
    (the IP that *triggered* the callback - usually the
    attacker's exfil node), ``user_agent``, and ``request_path``.
    The renderer surfaces both IPs because the operator value is
    the cross-reference: ``aws callback from 198.51.100.42 (orig
    203.0.113.7)`` tells them the same actor came back from a
    different network.
    """
    kind = event.get("kind", "unknown")
    callback_ip = event.get("callback_source_ip", "unknown")
    registered_ip = event.get("registered_source_ip")
    if isinstance(registered_ip, str) and registered_ip:
        return f"{kind} callback from {callback_ip} (orig {registered_ip})"
    return f"{kind} callback from {callback_ip}"


def _summarise_counter_deception_engaged(event: dict[str, Any]) -> str:
    """Render a bridge.counter_deception_engaged event for the alerts panel.

    The bridge emits ``mode`` (off / garble / timebomb / both),
    ``trigger`` (threat / pin), ``attacker_ip``, and ``threat_score``
    (null for a pin). The operator value is "which session got the
    deliberate-falsehood treatment and why": ``both via threat on
    203.0.113.7 (score 82)`` or ``garble via pin on 198.51.100.7``.
    """
    mode = event.get("mode", "unknown")
    trigger = event.get("trigger", "unknown")
    attacker_ip = event.get("attacker_ip", "unknown")
    score = event.get("threat_score")
    if isinstance(score, int):
        return f"{mode} via {trigger} on {attacker_ip} (score {score})"
    return f"{mode} via {trigger} on {attacker_ip}"


def _summarise_cluster_match(event: dict[str, Any]) -> str:
    matches = event.get("matches")
    count = len(matches) if isinstance(matches, list) else 0
    top = _top_match_similarity(matches)
    threshold = event.get("threshold")
    if top is not None and isinstance(threshold, (int, float)):
        return f"{count} similar session(s); top={top:.3f} (threshold={float(threshold):.2f})"
    return f"{count} similar session(s)"


def _top_match_similarity(matches: object) -> float | None:
    """Pull the first ``similarity`` value out of a matches list, if any."""
    if not isinstance(matches, list) or not matches:
        return None
    first = matches[0]
    if not isinstance(first, dict):
        return None
    sim = first.get("similarity")
    return float(sim) if isinstance(sim, (int, float)) else None


_SUMMARISERS: dict[str, Callable[[dict[str, Any]], str]] = {
    "defense_fired": _summarise_defense_fired,
    "defense_scan_truncated": _summarise_defense_scan_truncated,
    "subsystem_refused": _summarise_subsystem_refused,
    "high_severity_session": _summarise_high_severity_session,
    "persistence_attempt": _summarise_persistence_attempt,
    "intent_summary": _summarise_intent_summary,
    "cluster_match": _summarise_cluster_match,
    "honeytoken_callback_hit": _summarise_honeytoken_callback,
    "counter_deception_engaged": _summarise_counter_deception_engaged,
}


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
