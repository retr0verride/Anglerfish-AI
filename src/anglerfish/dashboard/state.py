"""Dashboard state - thin facade over :class:`SessionStore` + pub/sub fan-out.

Stage 4 moved persistence to :class:`anglerfish.sessions.SessionStore`.
This module keeps two responsibilities:

* **Write-through to the session store.** ``update_session``,
  ``end_session``, ``record_threat`` persist to SQLite and then
  publish the matching pub/sub event.
* **WebSocket fan-out.** ``subscribe()`` / ``publish()`` /
  ``subscriber_count()`` are unchanged from the pre-Stage-4 in-
  memory implementation. The pub/sub is intentionally ephemeral:
  subscribers receive events from the moment they subscribe until
  they iterate to exhaustion, and a service restart resets the
  set. Persistence is the store's job.

The constructor changed in Stage 4 to require a ``SessionStore``.
The optional ``max_active_sessions`` / ``command_history_size`` /
``threat_history_size`` knobs survive as read-path query caps so
existing call sites and tests don't break; they no longer bound
storage (the store is unbounded; ops can purge via SQL).
"""

from __future__ import annotations

import asyncio
import contextlib
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Final
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from anglerfish.config.models import CounterDeceptionMode
from anglerfish.honeytokens.schema import Honeytoken
from anglerfish.models.counter_deception_pin import CounterDeceptionPin
from anglerfish.models.embedding import SessionEmbedding
from anglerfish.models.intent import IntentSummary
from anglerfish.models.persistence import PersistenceEvent
from anglerfish.models.persona_pin import PersonaPin
from anglerfish.models.session import CommandTurn, SessionSnapshot
from anglerfish.models.threat import ThreatAssessment
from anglerfish.sessions import SessionStore

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
    INTENT = "intent"


class DashboardEvent(BaseModel):
    """One pub/sub message."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    kind: DashboardEventKind
    timestamp: datetime
    payload: dict[str, Any]


class DashboardStats(BaseModel):
    """Aggregate snapshot returned by ``/api/stats``.

    Shape is identical to :class:`anglerfish.sessions.SessionStoreStats`
    so the conversion is a field-by-field copy; the two types stay
    distinct so callers can depend on either without a coupling
    they don't want.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    active_sessions: int = Field(ge=0)
    total_commands_observed: int = Field(ge=0)
    total_threat_assessments: int = Field(ge=0)
    high_severity_count: int = Field(ge=0)
    persistence_attempt_count: int = Field(ge=0)


def _utcnow() -> datetime:
    return datetime.now(tz=UTC)


class DashboardState:
    """Persistence facade + pub/sub.

    Construct with a :class:`SessionStore` (already opened by the
    caller). Writes pass through to the store and then publish; reads
    are store queries with the configured caps applied.
    """

    def __init__(
        self,
        store: SessionStore,
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
        self._store = store
        self._max_active_sessions = max_active_sessions
        self._command_history_size = command_history_size
        self._threat_history_size = threat_history_size
        self._subscribers: set[asyncio.Queue[DashboardEvent]] = set()
        self._subscribers_lock = asyncio.Lock()

    @property
    def max_active_sessions(self) -> int:
        return self._max_active_sessions

    @property
    def store(self) -> SessionStore:
        """Expose the underlying store so routes can read directly.

        Used by the Stage 3 export endpoints (date-range queries
        cannot be expressed through the facade without bloating it)
        and by tests that want to assert persistence semantics
        without going through the facade's diff logic.
        """
        return self._store

    # ------------------------------------------------------------------
    # Publishing - called by bridge / threat engine.
    # ------------------------------------------------------------------

    async def publish(self, event: DashboardEvent) -> None:
        async with self._subscribers_lock:
            subscribers = tuple(self._subscribers)
        for queue in subscribers:
            try:
                queue.put_nowait(event)
            except asyncio.QueueFull:
                # Drop the oldest event in this subscriber's queue to make
                # space - slow consumers should fall behind, not stall.
                with _suppress_get_nowait(queue):
                    queue.put_nowait(event)

    async def update_session(self, snapshot: SessionSnapshot) -> None:
        # Diff against persisted state so the COMMAND events we
        # publish are accurate even after a process restart drops the
        # in-memory subscriber set.
        previous = await self._store.get_session(snapshot.session_id)
        existing_turns: tuple[CommandTurn, ...] = previous.turns if previous else ()
        await self._store.upsert_session(snapshot)
        added = snapshot.turns[len(existing_turns) :]
        for turn in added:
            await self._store.record_turn(snapshot.session_id, turn)

        event_kind = (
            DashboardEventKind.SESSION_UPDATED
            if previous is not None
            else DashboardEventKind.SESSION_STARTED
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
        previous = await self._store.get_session(session_id)
        if previous is None:
            return
        await self._store.end_session(session_id, _utcnow())
        await self.publish(
            DashboardEvent(
                kind=DashboardEventKind.SESSION_ENDED,
                timestamp=_utcnow(),
                payload=previous.model_dump(mode="json"),
            ),
        )

    async def record_threat(self, assessment: ThreatAssessment) -> None:
        await self._store.record_threat(assessment)
        await self.publish(
            DashboardEvent(
                kind=DashboardEventKind.THREAT,
                timestamp=_utcnow(),
                payload=assessment.model_dump(mode="json"),
            ),
        )

    async def upsert_intent(self, summary: IntentSummary) -> None:
        """Persist an :class:`IntentSummary` and publish an INTENT event."""
        await self._store.upsert_intent(summary)
        await self.publish(
            DashboardEvent(
                kind=DashboardEventKind.INTENT,
                timestamp=_utcnow(),
                payload=summary.model_dump(mode="json"),
            ),
        )

    async def get_intent(self, session_id: UUID) -> IntentSummary | None:
        return await self._store.get_intent(session_id)

    async def get_intents_in_range(
        self,
        *,
        start: datetime,
        end: datetime,
    ) -> list[IntentSummary]:
        return await self._store.get_intents_in_range(start=start, end=end)

    async def upsert_embedding(self, embedding: SessionEmbedding) -> None:
        """Persist a Stage 8 :class:`SessionEmbedding`.

        No pub/sub publish: the raw vector is not a user-facing event.
        Operators see clustering surface through the ``cluster_match``
        audit event (emitted by the tailer when ``find_similar``
        returns neighbours above the threshold) which Stage 8 slice 5
        will fan out to the alerts panel.
        """
        await self._store.upsert_embedding(embedding)

    async def get_embedding(self, session_id: UUID) -> SessionEmbedding | None:
        return await self._store.get_embedding(session_id)

    async def find_similar(
        self,
        session_id: UUID,
        *,
        k: int = 5,
        min_similarity: float = 0.85,
    ) -> list[tuple[SessionEmbedding, float]]:
        return await self._store.find_similar(
            session_id,
            k=k,
            min_similarity=min_similarity,
        )

    # ------------------------------------------------------------------
    # Persona pins + rebound (Stage 9 slice 9.4)
    # ------------------------------------------------------------------

    async def upsert_persona_pin(
        self,
        *,
        source_ip: str,
        persona: str,
        created_by: str,
    ) -> PersonaPin:
        """Pin ``source_ip`` to ``persona``; returns the persisted record."""
        return await self._store.upsert_persona_pin(
            source_ip=source_ip,
            persona=persona,
            created_by=created_by,
        )

    async def list_persona_pins(self) -> list[PersonaPin]:
        return await self._store.list_persona_pins()

    async def delete_persona_pin(self, source_ip: str) -> bool:
        return await self._store.delete_persona_pin(source_ip)

    # ------------------------------------------------------------------
    # Counter-deception pins (Stage 12 slice 12.4)
    # ------------------------------------------------------------------

    async def upsert_counter_deception_pin(
        self,
        *,
        source_ip: str,
        mode: CounterDeceptionMode,
        created_by: str,
    ) -> CounterDeceptionPin:
        """Pin ``source_ip`` to ``mode``; returns the persisted record."""
        return await self._store.upsert_counter_deception_pin(
            source_ip=source_ip,
            mode=mode,
            created_by=created_by,
        )

    async def list_counter_deception_pins(self) -> list[CounterDeceptionPin]:
        return await self._store.list_counter_deception_pins()

    async def delete_counter_deception_pin(self, source_ip: str) -> bool:
        return await self._store.delete_counter_deception_pin(source_ip)

    async def update_session_persona(self, session_id: UUID, persona: str) -> bool:
        """Rebound the persona on an already-persisted session row."""
        return await self._store.update_session_persona(session_id, persona)

    # ------------------------------------------------------------------
    # Fake persistence state (Stage 10 slice 10.2)
    # ------------------------------------------------------------------

    async def record_persistence_event(
        self,
        event: PersistenceEvent,
        *,
        source_ip: str,
        session_id: UUID,
        created_at: datetime,
    ) -> bool:
        """Persist a Stage 10 :class:`PersistenceEvent`.

        Returns True iff a new row was inserted; False on the
        replay-of-already-persisted-audit-line idempotent path.
        No pub/sub publish: persistence events surface to
        operators via the ``bridge.persistence_attempt`` audit
        event (already wired to the alerts panel since Stage 3),
        not via the WebSocket fan-out.
        """
        return await self._store.record_persistence_event(
            event,
            source_ip=source_ip,
            session_id=session_id,
            created_at=created_at,
        )

    async def list_persistence_events_for_source_ip(
        self,
        source_ip: str,
    ) -> list[PersistenceEvent]:
        return await self._store.list_persistence_events_for_source_ip(source_ip)

    # ------------------------------------------------------------------
    # Honeytokens (Stage 11 slice 11.2)
    # ------------------------------------------------------------------

    async def register_honeytoken(self, token: Honeytoken) -> bool:
        """Persist a Stage 11 :class:`Honeytoken`.

        Returns True iff a new row was inserted; False on the
        already-present-via-PK idempotent path. No pub/sub
        publish: honeytokens surface to operators via the
        existing alerts-panel ``honeytoken_callback_hit`` kind
        (live after slice 11.4), not via WebSocket fan-out.
        """
        return await self._store.register_honeytoken(token)

    async def get_honeytoken(self, token_id: str) -> Honeytoken | None:
        return await self._store.get_honeytoken(token_id)

    async def list_honeytokens_for_source_ip(
        self,
        source_ip: str,
    ) -> list[Honeytoken]:
        return await self._store.list_honeytokens_for_source_ip(source_ip)

    async def list_static_honeytokens(self) -> list[Honeytoken]:
        return await self._store.list_static_honeytokens()

    # ------------------------------------------------------------------
    # Queries - called by REST routes.
    # ------------------------------------------------------------------

    async def get_active_sessions(self) -> list[SessionSnapshot]:
        return await self._store.get_active_sessions(limit=self._max_active_sessions)

    async def get_session(self, session_id: UUID) -> SessionSnapshot | None:
        return await self._store.get_session(session_id)

    async def get_recent_commands(self, *, limit: int = 100) -> list[dict[str, Any]]:
        if limit <= 0:
            raise ValueError("limit must be positive")
        effective = min(limit, self._command_history_size)
        pairs = await self._store.get_recent_commands(limit=effective)
        return [
            {
                "session_id": str(sid),
                "command": turn.command,
                "response": turn.response,
                "source": str(turn.source),
                "timestamp": turn.timestamp.isoformat(),
                "latency_ms": turn.latency_ms,
            }
            for sid, turn in pairs
        ]

    async def get_recent_threats(self, *, limit: int = 50) -> list[ThreatAssessment]:
        if limit <= 0:
            raise ValueError("limit must be positive")
        effective = min(limit, self._threat_history_size)
        return await self._store.get_recent_threats(limit=effective)

    async def get_stats(self) -> DashboardStats:
        s = await self._store.get_stats()
        return DashboardStats(
            active_sessions=s.active_sessions,
            total_commands_observed=s.total_commands_observed,
            total_threat_assessments=s.total_threat_assessments,
            high_severity_count=s.high_severity_count,
            persistence_attempt_count=s.persistence_attempt_count,
        )

    # ------------------------------------------------------------------
    # Subscriptions - used by the WebSocket endpoint.
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
        async with self._subscribers_lock:
            self._subscribers.add(queue)
        try:
            yield queue
        finally:
            async with self._subscribers_lock:
                self._subscribers.discard(queue)

    async def subscriber_count(self) -> int:
        async with self._subscribers_lock:
            return len(self._subscribers)


def _suppress_get_nowait(queue: asyncio.Queue[DashboardEvent]) -> Any:
    """Context manager that drains one element from ``queue`` if present."""
    with contextlib.suppress(asyncio.QueueEmpty):
        queue.get_nowait()
        return contextlib.suppress(asyncio.QueueFull)
    return contextlib.nullcontext()
