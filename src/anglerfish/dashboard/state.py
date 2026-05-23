"""In-memory dashboard state and pub/sub fan-out.

Two responsibilities live here:

* A bounded cache of recent activity — active sessions, the latest
  threat assessments, a rolling command-history buffer — so REST
  callers don't have to hit the credential database or replay the
  JSONL fallback file for the common views.
* A WebSocket-facing pub/sub. Subscribers register an
  :class:`asyncio.Queue` (returned from :meth:`DashboardState.subscribe`)
  and receive every event published from the moment they subscribe
  until they iterate to exhaustion.

Both responsibilities are deliberately in-process. The dashboard runs
on the service NIC, talks to a single Anglerfish bridge, and does not
need a broker. Persistence is the forwarder's job.
"""

from __future__ import annotations

import asyncio
from collections import deque
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Final
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from anglerfish.models.session import CommandTurn, SessionSnapshot
from anglerfish.models.threat import ThreatAssessment

__all__ = [
    "DashboardEvent",
    "DashboardEventKind",
    "DashboardState",
    "DashboardStats",
]


_DEFAULT_HISTORY_SIZE: Final[int] = 1000
_DEFAULT_THREAT_HISTORY: Final[int] = 200
_DEFAULT_SUBSCRIBER_QUEUE: Final[int] = 256


class DashboardEventKind(StrEnum):
    SESSION_STARTED = "session_started"
    SESSION_UPDATED = "session_updated"
    SESSION_ENDED = "session_ended"
    COMMAND = "command"
    THREAT = "threat"


class DashboardEvent(BaseModel):
    """One pub/sub message."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    kind: DashboardEventKind
    timestamp: datetime
    payload: dict[str, Any]


class DashboardStats(BaseModel):
    """Aggregate snapshot used by the ``/api/stats`` endpoint."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    active_sessions: int = Field(ge=0)
    total_commands_observed: int = Field(ge=0)
    total_threat_assessments: int = Field(ge=0)
    high_severity_count: int = Field(ge=0)
    persistence_attempt_count: int = Field(ge=0)


def _utcnow() -> datetime:
    return datetime.now(tz=UTC)


class DashboardState:
    """Bounded in-memory state with WebSocket fan-out."""

    def __init__(
        self,
        *,
        max_active_sessions: int = 500,
        command_history_size: int = _DEFAULT_HISTORY_SIZE,
        threat_history_size: int = _DEFAULT_THREAT_HISTORY,
    ) -> None:
        if max_active_sessions <= 0:
            raise ValueError("max_active_sessions must be positive")
        if command_history_size <= 0:
            raise ValueError("command_history_size must be positive")
        if threat_history_size <= 0:
            raise ValueError("threat_history_size must be positive")
        self._max_active_sessions = max_active_sessions
        self._active_sessions: dict[UUID, SessionSnapshot] = {}
        self._command_history: deque[tuple[UUID, CommandTurn]] = deque(
            maxlen=command_history_size,
        )
        self._threats: dict[UUID, ThreatAssessment] = {}
        self._threat_order: deque[UUID] = deque(maxlen=threat_history_size)
        self._total_commands = 0
        self._lock = asyncio.Lock()
        self._subscribers: set[asyncio.Queue[DashboardEvent]] = set()

    @property
    def max_active_sessions(self) -> int:
        return self._max_active_sessions

    # ------------------------------------------------------------------
    # Publishing — called by bridge / threat engine.
    # ------------------------------------------------------------------

    async def publish(self, event: DashboardEvent) -> None:
        async with self._lock:
            subscribers = tuple(self._subscribers)
        for queue in subscribers:
            try:
                queue.put_nowait(event)
            except asyncio.QueueFull:
                # Drop the oldest event in this subscriber's queue to make
                # space — slow consumers should fall behind, not stall.
                with _suppress_get_nowait(queue):
                    queue.put_nowait(event)

    async def update_session(self, snapshot: SessionSnapshot) -> None:
        async with self._lock:
            previously_known = snapshot.session_id in self._active_sessions
            # Snapshot the prior turns BEFORE overwriting active_sessions —
            # _previous_turns reads from that same dict.
            existing_turns: tuple[CommandTurn, ...] = (
                self._previous_turns(snapshot.session_id) if previously_known else ()
            )
            self._active_sessions[snapshot.session_id] = snapshot
            self._enforce_session_cap()

            new_turns = snapshot.turns
            added = new_turns[len(existing_turns) :]
            for turn in added:
                self._command_history.append((snapshot.session_id, turn))
                self._total_commands += 1

        event_kind = (
            DashboardEventKind.SESSION_STARTED
            if not previously_known
            else DashboardEventKind.SESSION_UPDATED
        )
        await self.publish(
            DashboardEvent(
                kind=event_kind,
                timestamp=_utcnow(),
                payload=snapshot.model_dump(mode="json"),
            ),
        )
        for turn in added:
            await self.publish(
                DashboardEvent(
                    kind=DashboardEventKind.COMMAND,
                    timestamp=turn.timestamp,
                    payload={
                        "session_id": str(snapshot.session_id),
                        "command": turn.command,
                        "response": turn.response,
                        "source": str(turn.source),
                        "latency_ms": turn.latency_ms,
                    },
                ),
            )

    async def end_session(self, session_id: UUID) -> None:
        async with self._lock:
            removed = self._active_sessions.pop(session_id, None)
        if removed is not None:
            await self.publish(
                DashboardEvent(
                    kind=DashboardEventKind.SESSION_ENDED,
                    timestamp=_utcnow(),
                    payload=removed.model_dump(mode="json"),
                ),
            )

    async def record_threat(self, assessment: ThreatAssessment) -> None:
        async with self._lock:
            if assessment.session_id not in self._threats:
                self._threat_order.append(assessment.session_id)
            self._threats[assessment.session_id] = assessment
            self._evict_threats_locked()
        await self.publish(
            DashboardEvent(
                kind=DashboardEventKind.THREAT,
                timestamp=_utcnow(),
                payload=assessment.model_dump(mode="json"),
            ),
        )

    # ------------------------------------------------------------------
    # Queries — called by REST routes.
    # ------------------------------------------------------------------

    async def get_active_sessions(self) -> list[SessionSnapshot]:
        async with self._lock:
            return sorted(
                self._active_sessions.values(),
                key=lambda s: s.last_activity_at,
                reverse=True,
            )

    async def get_session(self, session_id: UUID) -> SessionSnapshot | None:
        async with self._lock:
            return self._active_sessions.get(session_id)

    async def get_recent_commands(self, *, limit: int = 100) -> list[dict[str, Any]]:
        if limit <= 0:
            raise ValueError("limit must be positive")
        async with self._lock:
            tail = list(self._command_history)[-limit:]
        tail.reverse()
        return [
            {
                "session_id": str(sid),
                "command": turn.command,
                "response": turn.response,
                "source": str(turn.source),
                "timestamp": turn.timestamp.isoformat(),
                "latency_ms": turn.latency_ms,
            }
            for sid, turn in tail
        ]

    async def get_recent_threats(
        self,
        *,
        limit: int = 50,
    ) -> list[ThreatAssessment]:
        if limit <= 0:
            raise ValueError("limit must be positive")
        async with self._lock:
            ordered = list(self._threat_order)[-limit:]
            ordered.reverse()
            return [self._threats[sid] for sid in ordered if sid in self._threats]

    async def get_stats(self) -> DashboardStats:
        async with self._lock:
            active = len(self._active_sessions)
            total_threats = len(self._threats)
            high_sev = sum(1 for a in self._threats.values() if a.high_severity)
            persistence = sum(1 for a in self._threats.values() if a.persistence_attempted)
            commands = self._total_commands
        return DashboardStats(
            active_sessions=active,
            total_commands_observed=commands,
            total_threat_assessments=total_threats,
            high_severity_count=high_sev,
            persistence_attempt_count=persistence,
        )

    # ------------------------------------------------------------------
    # Subscriptions — used by the WebSocket endpoint.
    # ------------------------------------------------------------------

    @asynccontextmanager
    async def subscribe(
        self,
        *,
        queue_size: int = _DEFAULT_SUBSCRIBER_QUEUE,
    ) -> AsyncIterator[asyncio.Queue[DashboardEvent]]:
        if queue_size <= 0:
            raise ValueError("queue_size must be positive")
        queue: asyncio.Queue[DashboardEvent] = asyncio.Queue(maxsize=queue_size)
        async with self._lock:
            self._subscribers.add(queue)
        try:
            yield queue
        finally:
            async with self._lock:
                self._subscribers.discard(queue)

    async def subscriber_count(self) -> int:
        async with self._lock:
            return len(self._subscribers)

    # ------------------------------------------------------------------
    # Internal helpers (assume lock held).
    # ------------------------------------------------------------------

    def _previous_turns(self, session_id: UUID) -> tuple[CommandTurn, ...]:
        prev = self._active_sessions.get(session_id)
        return prev.turns if prev is not None else ()

    def _enforce_session_cap(self) -> None:
        if len(self._active_sessions) <= self._max_active_sessions:
            return
        # Drop the oldest sessions by last_activity_at.
        excess = len(self._active_sessions) - self._max_active_sessions
        victims = sorted(
            self._active_sessions.items(),
            key=lambda item: item[1].last_activity_at,
        )[:excess]
        for sid, _snap in victims:
            del self._active_sessions[sid]

    def _evict_threats_locked(self) -> None:
        # deque already enforces maxlen on _threat_order. We need to also
        # drop threats no longer in the order deque from the dict.
        live = set(self._threat_order)
        stale = [sid for sid in self._threats if sid not in live]
        for sid in stale:
            del self._threats[sid]


def _suppress_get_nowait(queue: asyncio.Queue[DashboardEvent]) -> Any:
    """Context manager that drains one element from ``queue`` if present."""
    from contextlib import nullcontext, suppress

    try:
        queue.get_nowait()
        return suppress(asyncio.QueueFull)
    except asyncio.QueueEmpty:
        return nullcontext()
