"""Subsystem health probes for the dashboard's authenticated health panel.

Two read-only endpoints sit on top of these helpers:

* ``GET /api/health/ollama`` reports Ollama reachability plus the
  most recent model-integrity check outcome read from the audit log.
* ``GET /api/health/sessions`` reports active session count vs the
  bridge's configured concurrency cap and a token-per-minute rate
  derived from recent ``bridge.command_*`` / ``lure.command_*``
  audit events.

The ``GET /api/health/forwarder`` endpoint was removed alongside
the Cowrie integration (the forwarder package was Cowrie's only
production caller). Operators on installs that ran Cowrie before
the deletion can use :func:`anglerfish.sessions.import_jsonl_into_store`
to replay the historical JSONL fallback file into the session
store; see ``docs/RUNBOOK.md`` "Import old forwarder JSONL".

Every probe is best-effort: a missing audit log or an unreachable
Ollama produces a defined JSON response (``"unknown"`` / ``null`` /
``0``) rather than a 500.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any

import httpx

from anglerfish.dashboard.audit_reader import iter_events, parse_event_timestamp

if TYPE_CHECKING:
    from anglerfish.audit import AuditLog
    from anglerfish.config.settings import AnglerfishSettings
    from anglerfish.dashboard.state import DashboardState

__all__ = [
    "ollama_health",
    "sessions_health",
]


_OLLAMA_PROBE_TIMEOUT_S = 2.0
_SESSION_RATE_WINDOW_MIN = 5
_COMMAND_EVENT_TYPES = frozenset(
    {
        "bridge.command_native",
        "bridge.command_bridge",
        "lure.command_native",
        "lure.command_bridge",
    },
)
_INTEGRITY_EVENT_TYPES = frozenset(
    {
        "bridge.model_integrity_verified",
        "bridge.model_integrity_failed",
        "bridge.model_integrity_skipped",
    },
)
_WARMUP_EVENT_TYPES = frozenset({"llm.warmup_succeeded", "llm.warmup_failed"})
_WASTING_WINDOW_MIN = 60
_WASTING_APPLIED_EVENT = "bridge.wasting_applied"
_WASTING_EXHAUSTED_EVENT = "bridge.wasting_budget_exhausted"
_SESSION_CLOSED_EVENT = "lure.session_closed"


async def ollama_health(
    settings: AnglerfishSettings,
    audit_log: AuditLog,
    *,
    http_client: httpx.AsyncClient | None = None,
) -> dict[str, Any]:
    """Probe Ollama with a short-timeout GET and read the latest integrity result."""
    base_url = str(settings.ollama.base_url)
    reachable, checked_at = await _probe_ollama(base_url, http_client=http_client)
    integrity = _latest_integrity_check(audit_log.path)
    warmup = _latest_warmup_per_role(audit_log.path)
    return {
        "reachable": reachable,
        "reachable_at": checked_at,
        "models": [
            {
                "role": "fast",
                "model": settings.ollama.fast_model,
                "warmed_at": warmup.get("fast", {}).get("warmed_at"),
                "last_warmup_status": warmup.get("fast", {}).get("status"),
            },
            {
                "role": "deep",
                "model": settings.ollama.deep_model,
                "warmed_at": warmup.get("deep", {}).get("warmed_at"),
                "last_warmup_status": warmup.get("deep", {}).get("status"),
            },
        ],
        "integrity_check": integrity,
    }


async def sessions_health(
    settings: AnglerfishSettings,
    dashboard_state: DashboardState,
    audit_log: AuditLog,
) -> dict[str, Any]:
    """Report active sessions vs cap + a tokens-per-minute rate.

    Token rate counts ``bridge.command_*`` + ``lure.command_*`` audit
    events in the last :data:`_SESSION_RATE_WINDOW_MIN` minutes and
    divides by the window. Commands, not tokens; the field is named
    ``tokens_per_minute`` per the design doc because that's the
    operator-meaningful number, and one command roughly equals one
    LLM round-trip until the Stage 5 leverage layer ships streaming.
    """
    stats = await dashboard_state.get_stats()
    cap = settings.rate_limit.max_concurrent_requests
    active = stats.active_sessions
    utilisation_pct = (active / cap * 100.0) if cap > 0 else 0.0
    rate = _command_rate_per_minute(audit_log.path, _SESSION_RATE_WINDOW_MIN)
    wasting = _wasting_stats(audit_log.path, settings.bridge.wasting_strategy)
    return {
        "active_sessions": active,
        "max_concurrent_requests": cap,
        "utilisation_pct": round(utilisation_pct, 1),
        "tokens_per_minute": {
            "window_minutes": _SESSION_RATE_WINDOW_MIN,
            "rate": rate,
        },
        "wasting": wasting,
    }


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------


async def _probe_ollama(
    base_url: str,
    *,
    http_client: httpx.AsyncClient | None,
) -> tuple[bool, str | None]:
    """GET the Ollama base URL with a short timeout. Returns (reachable, iso_ts)."""
    owns_client = http_client is None
    client = http_client or httpx.AsyncClient(timeout=_OLLAMA_PROBE_TIMEOUT_S)
    try:
        try:
            response = await client.get(base_url)
        except (TimeoutError, httpx.HTTPError):
            return False, None
        reachable = response.status_code < 500
        return reachable, datetime.now(tz=UTC).isoformat()
    finally:
        if owns_client:
            await client.aclose()


def _latest_integrity_check(audit_path: Path) -> dict[str, Any]:
    """Find the most recent integrity-check event in the audit log."""
    for event in iter_events(audit_path):
        event_type = event.get("event_type")
        if event_type not in _INTEGRITY_EVENT_TYPES:
            continue
        status = {
            "bridge.model_integrity_verified": "passed",
            "bridge.model_integrity_failed": "failed",
            "bridge.model_integrity_skipped": "skipped",
        }[str(event_type)]
        return {
            "status": status,
            "last_checked_at": event.get("ts"),
            "expected_hash_present": event_type != "bridge.model_integrity_skipped",
        }
    return {
        "status": "unknown",
        "last_checked_at": None,
        "expected_hash_present": False,
    }


def _latest_warmup_per_role(audit_path: Path) -> dict[str, dict[str, Any]]:
    """Return ``{role: {warmed_at, status}}`` from the most recent warmup events.

    ``status`` is ``"succeeded"`` or ``"failed"`` based on the event type.
    ``warmed_at`` is the audit-event wall-clock timestamp string. Roles
    with no recorded warmup yet are omitted from the result.
    """
    latest: dict[str, dict[str, Any]] = {}
    for event in iter_events(audit_path):
        event_type = event.get("event_type")
        if event_type not in _WARMUP_EVENT_TYPES:
            continue
        role = event.get("role")
        if not isinstance(role, str) or role in latest:
            continue
        latest[role] = {
            "warmed_at": event.get("ts"),
            "status": "succeeded" if event_type == "llm.warmup_succeeded" else "failed",
        }
    return latest


def _wasting_stats(audit_path: Path, static_strategy: str) -> dict[str, Any]:
    """Aggregate per-session wasting stats from the audit log.

    Scans ``bridge.wasting_applied`` + ``bridge.wasting_budget_exhausted``
    events within the last :data:`_WASTING_WINDOW_MIN` minutes. Returns:

    * ``strategy`` - the bridge's static config (cross-process; the
      runtime-overrides JSON is the source of truth at request time
      but the dashboard doesn't share that file's read path here).
    * ``avg_wasted_ms_per_session`` - sum of wasted_ms over all
      applied events in window, divided by distinct session_ids.
    * ``sessions_at_budget_cap`` - count of distinct session_ids
      that emitted ``bridge.wasting_budget_exhausted`` and have not
      since emitted ``lure.session_closed``.

    Missing audit log or empty window returns zeroed counters.
    """
    now = datetime.now(tz=UTC)
    cutoff = now - timedelta(minutes=_WASTING_WINDOW_MIN)

    total_wasted_ms = 0
    sessions_with_wasting: set[str] = set()
    sessions_exhausted: set[str] = set()
    sessions_closed: set[str] = set()

    for event in iter_events(audit_path):
        event_type = event.get("event_type")
        if event_type not in (
            _WASTING_APPLIED_EVENT,
            _WASTING_EXHAUSTED_EVENT,
            _SESSION_CLOSED_EVENT,
        ):
            continue
        ts = parse_event_timestamp(event)
        if ts is None or ts < cutoff:
            continue
        session_id = event.get("session_id")
        if not isinstance(session_id, str):
            continue
        if event_type == _WASTING_APPLIED_EVENT:
            sessions_with_wasting.add(session_id)
            wasted = event.get("wasted_ms")
            if isinstance(wasted, int):
                total_wasted_ms += wasted
        elif event_type == _WASTING_EXHAUSTED_EVENT:
            sessions_exhausted.add(session_id)
        else:  # _SESSION_CLOSED_EVENT
            sessions_closed.add(session_id)

    distinct = len(sessions_with_wasting)
    avg = total_wasted_ms // distinct if distinct > 0 else 0
    still_capped = sessions_exhausted - sessions_closed
    return {
        "strategy": static_strategy,
        "window_minutes": _WASTING_WINDOW_MIN,
        "avg_wasted_ms_per_session": avg,
        "sessions_at_budget_cap": len(still_capped),
    }


def _command_rate_per_minute(audit_path: Path, window_minutes: int) -> float:
    """Count command events in the last ``window_minutes`` and normalise."""
    if window_minutes <= 0:
        return 0.0
    now = datetime.now(tz=UTC)
    cutoff = now - timedelta(minutes=window_minutes)
    count = 0
    for event in iter_events(audit_path):
        event_type = event.get("event_type")
        if event_type not in _COMMAND_EVENT_TYPES:
            continue
        ts = parse_event_timestamp(event)
        if ts is None:
            continue
        if ts < cutoff:
            break  # newest-first iteration; older events are out of the window
        count += 1
    return round(count / window_minutes, 2)
