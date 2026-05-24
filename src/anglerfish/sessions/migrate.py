"""One-shot helper to import the forwarder's JSONL fallback into the store.

Operators that upgraded to Stage 4 from an earlier release have a
``/var/lib/anglerfish/sessions.jsonl`` (the forwarder fallback file
written when Splunk HEC is unreachable). The lines are individual
event envelopes, not session snapshots; this module reconstructs
sessions by grouping events by ``session`` (Cowrie's session-id
field) and replaying ``connect`` / ``input`` / ``closed`` events
into the store via the regular write API.

Intentionally not a CLI subcommand - the operation is one-shot per
install and would otherwise be permanent maintenance surface in the
typer parser. The :func:`import_jsonl_into_store` helper is the
durable interface; the ``docs/RUNBOOK.md`` "Data migration" section
documents the one-liner.

Lines that fail Pydantic validation (malformed event, unrecognised
shape, truncated mid-write) are logged at warning and skipped. The
import is best-effort: a partial corpus is better than refusing to
start on a single bad line.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any
from uuid import UUID, uuid4

from anglerfish.models.session import CommandTurn, ResponseSource, SessionSnapshot

if TYPE_CHECKING:
    from anglerfish.sessions.store import SessionStore

__all__ = ["import_jsonl_into_store"]


_logger = logging.getLogger(__name__)

# Cowrie event identifiers we recognise. Other event ids in the
# fallback log are ignored (they belong to other Cowrie subsystems
# like TTY logging that don't translate to a SessionSnapshot).
_EVT_CONNECT = "cowrie.session.connect"
_EVT_COMMAND = "cowrie.command.input"
_EVT_CLOSED = "cowrie.session.closed"
_RECOGNISED_EVENTS = frozenset({_EVT_CONNECT, _EVT_COMMAND, _EVT_CLOSED})


@dataclass
class _Accumulator:
    """Per-session work-in-progress while iterating the JSONL file."""

    session_id: UUID
    source_ip: str = "unknown"
    username: str = "root"
    started_at: datetime = field(default_factory=lambda: datetime.now(tz=UTC))
    last_activity_at: datetime = field(default_factory=lambda: datetime.now(tz=UTC))
    ended_at: datetime | None = None
    turns: list[CommandTurn] = field(default_factory=list)


async def import_jsonl_into_store(
    path: Path,
    store: SessionStore,
    *,
    batch_size: int = 1000,
) -> int:
    """Read ``path`` and write reconstructed sessions to ``store``.

    Returns the number of sessions imported (i.e. the count of
    distinct Cowrie ``session`` ids that produced at least one
    valid event).

    ``batch_size`` caps the in-memory accumulator dictionary so a
    multi-GB fallback file does not OOM the process. When the cap
    is hit, completed-and-closed sessions are flushed to the store
    and dropped from the accumulator; sessions still receiving
    events stay until they close or the file ends.

    The store must already be open. The caller owns its lifecycle.
    """
    # One-shot pre-check; sync filesystem call is fine here because
    # this is operator-invoked migration, not a hot path.
    if not path.is_file():  # noqa: ASYNC240 - one-shot operator helper
        raise FileNotFoundError(f"JSONL fallback not found at {path!s}")
    if batch_size <= 0:
        raise ValueError(f"batch_size must be positive, got {batch_size}")

    accumulators: dict[str, _Accumulator] = {}
    imported = 0

    for event in _iter_events(path):
        cowrie_sid = event.get("session")
        eventid = event.get("eventid")
        if not isinstance(cowrie_sid, str) or eventid not in _RECOGNISED_EVENTS:
            continue
        acc = accumulators.setdefault(
            cowrie_sid,
            _Accumulator(session_id=uuid4()),
        )
        _apply_event(acc, event, eventid)

        # Flush closed sessions when we hit the working-set cap.
        if len(accumulators) >= batch_size:
            imported += await _flush_closed(accumulators, store)

    # Drain whatever remains: closed sessions get end_session, open
    # sessions get upserted as-is (operator can see they were active
    # when the fallback was written).
    imported += await _flush_all(accumulators, store)
    _logger.info("session migration: imported %s sessions from %s", imported, path)
    return imported


def _iter_events(path: Path) -> Iterable[dict[str, Any]]:
    """Yield parsed event dicts; skip malformed lines with a warning."""
    with path.open("r", encoding="utf-8", errors="replace") as fp:
        for line_no, raw in enumerate(fp, start=1):
            stripped = raw.strip()
            if not stripped:
                continue
            try:
                envelope = json.loads(stripped)
            except json.JSONDecodeError as exc:
                _logger.warning(
                    "session migration: skipping line %s of %s (%s)",
                    line_no,
                    path,
                    exc,
                )
                continue
            event = _unwrap_event(envelope)
            if event is not None:
                yield event


def _unwrap_event(envelope: Any) -> dict[str, Any] | None:
    """Peel the forwarder envelope (or accept a bare event) to a dict."""
    if not isinstance(envelope, dict):
        return None
    inner = envelope.get("event")
    if isinstance(inner, dict):
        return inner
    # Some lines are bare events (older forwarder versions, custom
    # imports); accept them too.
    if "eventid" in envelope:
        return envelope
    return None


def _apply_event(acc: _Accumulator, event: dict[str, Any], eventid: str) -> None:
    ts = _parse_timestamp(event.get("timestamp"))
    if ts is not None:
        acc.last_activity_at = ts

    if eventid == _EVT_CONNECT:
        if ts is not None:
            acc.started_at = ts
        src_ip = event.get("src_ip")
        if isinstance(src_ip, str) and src_ip:
            acc.source_ip = src_ip
        username = event.get("username")
        if isinstance(username, str) and username:
            acc.username = username
    elif eventid == _EVT_COMMAND:
        command = event.get("input")
        if not isinstance(command, str):
            return
        response = event.get("response")
        response_str = response if isinstance(response, str) else ""
        turn_ts = ts if ts is not None else acc.last_activity_at
        acc.turns.append(
            CommandTurn(
                command=command,
                response=response_str,
                source=ResponseSource.AI,
                timestamp=turn_ts,
                latency_ms=0.0,
            ),
        )
    elif eventid == _EVT_CLOSED:
        acc.ended_at = ts if ts is not None else acc.last_activity_at


def _parse_timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed


async def _flush_closed(
    accumulators: dict[str, _Accumulator],
    store: SessionStore,
) -> int:
    """Flush only the closed sessions; keep the live ones in the dict."""
    closed_keys = [k for k, acc in accumulators.items() if acc.ended_at is not None]
    if not closed_keys:
        return 0
    flushed = 0
    for key in closed_keys:
        await _write_accumulator(accumulators[key], store)
        del accumulators[key]
        flushed += 1
    return flushed


async def _flush_all(
    accumulators: dict[str, _Accumulator],
    store: SessionStore,
) -> int:
    """Final drain: write every remaining accumulator (closed and open)."""
    flushed = 0
    for acc in accumulators.values():
        await _write_accumulator(acc, store)
        flushed += 1
    accumulators.clear()
    return flushed


async def _write_accumulator(acc: _Accumulator, store: SessionStore) -> None:
    snapshot = SessionSnapshot(
        session_id=acc.session_id,
        source_ip=acc.source_ip,
        username=acc.username,
        fake_hostname="imported",  # we did not see this in the fallback envelope
        fake_username=acc.username,
        fake_cwd="/root",
        started_at=acc.started_at,
        last_activity_at=acc.last_activity_at,
        turns=tuple(acc.turns),
    )
    await store.upsert_session(snapshot)
    for turn in acc.turns:
        await store.record_turn(acc.session_id, turn)
    if acc.ended_at is not None:
        await store.end_session(acc.session_id, acc.ended_at)
