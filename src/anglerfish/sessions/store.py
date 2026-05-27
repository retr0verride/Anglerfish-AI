"""Async SQLite-backed persistent session + turn + threat store.

Mirrors the shape of :class:`anglerfish.credentials.storage.CredentialStore`:
single connection per process, all SQL work runs under
:func:`asyncio.to_thread`, mutations serialised by an
:class:`asyncio.Lock`, async-context-manager entry/exit.

The store is the operator-facing source of truth for everything the
dashboard reads about sessions, turns, and threats. It does NOT
own the WebSocket pub/sub fan-out; that stays in
:class:`anglerfish.dashboard.state.DashboardState` (which now uses
this store under the hood).

Schema lives in :mod:`anglerfish.sessions.schema`. The store calls
``run_migrations`` from :meth:`open`; schema bumps in future stages
add migration entries there and the store picks them up at next
boot.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import math
import os
import sqlite3
import struct
from collections.abc import Sequence
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Self
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from anglerfish.honeytokens.schema import Honeytoken
from anglerfish.models.embedding import SessionEmbedding
from anglerfish.models.intent import IntentSummary
from anglerfish.models.persistence import PersistenceEvent
from anglerfish.models.persona_pin import PersonaPin
from anglerfish.models.session import CommandTurn, ResponseSource, SessionSnapshot
from anglerfish.models.threat import ThreatAssessment, ThreatTechnique
from anglerfish.sessions.schema import PRAGMAS, run_migrations

if TYPE_CHECKING:
    from anglerfish.config.models import SessionStoreConfig

__all__ = [
    "SessionStore",
    "SessionStoreStats",
]


_logger = logging.getLogger(__name__)


class SessionStoreStats(BaseModel):
    """Aggregate snapshot, parity with :class:`DashboardStats`."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    active_sessions: int = Field(ge=0)
    total_commands_observed: int = Field(ge=0)
    total_threat_assessments: int = Field(ge=0)
    high_severity_count: int = Field(ge=0)
    persistence_attempt_count: int = Field(ge=0)


class SessionStore:
    """SQLite-backed session store. Construct once, share per process."""

    def __init__(self, config: SessionStoreConfig) -> None:
        self._config = config
        self._conn: sqlite3.Connection | None = None
        self._lock = asyncio.Lock()

    # -----------------------------------------------------------------
    # Lifecycle
    # -----------------------------------------------------------------

    @property
    def config(self) -> SessionStoreConfig:
        return self._config

    @property
    def is_open(self) -> bool:
        return self._conn is not None

    async def open(self) -> None:
        """Open (or create) the database and run schema migrations.

        Idempotent: a second call while already open is a no-op.
        """
        async with self._lock:
            if self._conn is not None:
                return
            await asyncio.to_thread(self._open_locked)

    def _open_locked(self) -> None:
        path = self._config.database_path
        path.parent.mkdir(parents=True, exist_ok=True)
        new_file = not path.exists()
        conn = sqlite3.connect(
            str(path),
            isolation_level=None,  # autocommit; WAL handles concurrency
            check_same_thread=False,
        )
        try:
            for pragma in PRAGMAS:
                conn.execute(pragma)
            run_migrations(conn)
        except sqlite3.Error:
            conn.close()
            raise
        if new_file:
            with contextlib.suppress(OSError):
                os.chmod(path, 0o600)
        self._conn = conn

    async def aclose(self) -> None:
        async with self._lock:
            if self._conn is None:
                return
            conn = self._conn
            self._conn = None
            await asyncio.to_thread(conn.close)

    async def __aenter__(self) -> Self:
        await self.open()
        return self

    async def __aexit__(self, *_exc: object) -> None:
        await self.aclose()

    # -----------------------------------------------------------------
    # Writes
    # -----------------------------------------------------------------

    async def upsert_session(self, snapshot: SessionSnapshot) -> None:
        """Insert or update a session row by ``session_id``.

        Stage 4 design: writers (the bridge / lure indirectly via
        DashboardState) call this on every snapshot. Turns are
        recorded separately via :meth:`record_turn` so callers can
        append one at a time without dragging the whole turn list
        through. command_count is set from the snapshot's turns
        tuple length for the convenience of dashboard queries.
        """
        self._require_open()
        async with self._lock:
            await asyncio.to_thread(self._upsert_session_locked, snapshot)

    def _upsert_session_locked(self, snapshot: SessionSnapshot) -> None:
        assert self._conn is not None  # noqa: S101
        # command_count is maintained by record_turn, not here. The
        # initial INSERT uses the snapshot's turn count so a bulk
        # import (migration) gets the right number without a per-turn
        # record_turn call; the ON CONFLICT path deliberately omits
        # command_count so live updates (which DO call record_turn
        # per added turn) don't double-count.
        self._conn.execute(
            """
            INSERT INTO sessions (
                session_id, source_ip, username, fake_hostname, fake_username,
                fake_cwd, started_at, last_activity_at, ended_at, command_count,
                persona
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, ?)
            ON CONFLICT(session_id) DO UPDATE SET
                source_ip        = excluded.source_ip,
                username         = excluded.username,
                fake_hostname    = excluded.fake_hostname,
                fake_username    = excluded.fake_username,
                fake_cwd         = excluded.fake_cwd,
                last_activity_at = excluded.last_activity_at,
                persona          = excluded.persona
            """,
            (
                str(snapshot.session_id),
                snapshot.source_ip,
                snapshot.username,
                snapshot.fake_hostname,
                snapshot.fake_username,
                snapshot.fake_cwd,
                snapshot.started_at.isoformat(),
                snapshot.last_activity_at.isoformat(),
                len(snapshot.turns),
                snapshot.persona_name,
            ),
        )

    async def record_turn(self, session_id: UUID, turn: CommandTurn) -> None:
        """Append one turn to a session. Sequence number is auto-assigned.

        UNIQUE(session_id, sequence_n) ensures gap-free monotonic
        sequencing. The next sequence_n is computed inside the lock
        so concurrent appends from the same dashboard process are
        serialised; cross-process serialisation comes from SQLite's
        WAL lock.
        """
        self._require_open()
        async with self._lock:
            await asyncio.to_thread(self._record_turn_locked, session_id, turn)

    def _record_turn_locked(self, session_id: UUID, turn: CommandTurn) -> None:
        assert self._conn is not None  # noqa: S101
        sid = str(session_id)
        cur = self._conn.execute(
            "SELECT COALESCE(MAX(sequence_n), 0) + 1 FROM turns WHERE session_id = ?",
            (sid,),
        )
        (next_seq,) = cur.fetchone()
        self._conn.execute(
            """
            INSERT INTO turns (
                session_id, sequence_n, command, response, source, timestamp, latency_ms
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                sid,
                int(next_seq),
                turn.command,
                turn.response,
                str(turn.source),
                turn.timestamp.isoformat(),
                turn.latency_ms,
            ),
        )
        # Keep command_count on sessions in sync so queries can use it
        # without a JOIN. Single UPDATE; cheap.
        self._conn.execute(
            "UPDATE sessions SET command_count = command_count + 1 WHERE session_id = ?",
            (sid,),
        )

    async def record_threat(self, assessment: ThreatAssessment) -> None:
        """Upsert a threat assessment for a session. FK to ``sessions`` enforced."""
        self._require_open()
        async with self._lock:
            await asyncio.to_thread(self._record_threat_locked, assessment)

    def _record_threat_locked(self, assessment: ThreatAssessment) -> None:
        assert self._conn is not None  # noqa: S101
        techniques_json = json.dumps(
            [
                {
                    "id": t.id,
                    "name": t.name,
                    "matches": list(t.matches),
                }
                for t in assessment.techniques
            ],
            separators=(",", ":"),
        )
        notes_json = json.dumps(list(assessment.notes), separators=(",", ":"))
        now_iso = _utcnow_iso()
        self._conn.execute(
            """
            INSERT INTO threats (
                session_id, score, persistence_attempted, high_severity,
                techniques_json, notes_json, last_updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(session_id) DO UPDATE SET
                score                 = excluded.score,
                persistence_attempted = excluded.persistence_attempted,
                high_severity         = excluded.high_severity,
                techniques_json       = excluded.techniques_json,
                notes_json            = excluded.notes_json,
                last_updated_at       = excluded.last_updated_at
            """,
            (
                str(assessment.session_id),
                assessment.score,
                1 if assessment.persistence_attempted else 0,
                1 if assessment.high_severity else 0,
                techniques_json,
                notes_json,
                now_iso,
            ),
        )

    async def upsert_intent(self, summary: IntentSummary) -> None:
        """Persist an :class:`IntentSummary` keyed by ``session_id``.

        FK to the ``sessions`` row is enforced (cascade-delete);
        callers must have already persisted the session itself.
        Repeated calls for the same session overwrite the row -
        Stage 7 produces at most one summary per session today, but
        the schema does not lock that invariant in.
        """
        self._require_open()
        async with self._lock:
            await asyncio.to_thread(self._upsert_intent_locked, summary)

    def _upsert_intent_locked(self, summary: IntentSummary) -> None:
        assert self._conn is not None  # noqa: S101
        techniques_json = json.dumps(list(summary.matched_techniques), separators=(",", ":"))
        self._conn.execute(
            """
            INSERT INTO intents (
                session_id, actor_profile, intent, why,
                matched_techniques_json, confidence, summary, extracted_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(session_id) DO UPDATE SET
                actor_profile           = excluded.actor_profile,
                intent                  = excluded.intent,
                why                     = excluded.why,
                matched_techniques_json = excluded.matched_techniques_json,
                confidence              = excluded.confidence,
                summary                 = excluded.summary,
                extracted_at            = excluded.extracted_at
            """,
            (
                str(summary.session_id),
                summary.actor_profile,
                summary.intent,
                summary.why,
                techniques_json,
                summary.confidence,
                summary.summary,
                summary.extracted_at.isoformat(),
            ),
        )

    async def end_session(self, session_id: UUID, ended_at: datetime) -> None:
        """Mark a session as ended. Subsequent active-list queries exclude it."""
        self._require_open()
        async with self._lock:
            await asyncio.to_thread(self._end_session_locked, session_id, ended_at)

    def _end_session_locked(self, session_id: UUID, ended_at: datetime) -> None:
        assert self._conn is not None  # noqa: S101
        self._conn.execute(
            "UPDATE sessions SET ended_at = ? WHERE session_id = ?",
            (ended_at.isoformat(), str(session_id)),
        )

    # -----------------------------------------------------------------
    # Reads
    # -----------------------------------------------------------------

    async def get_session(self, session_id: UUID) -> SessionSnapshot | None:
        """Return one session's snapshot including all its turns, or None."""
        self._require_open()
        async with self._lock:
            return await asyncio.to_thread(self._get_session_locked, session_id)

    def _get_session_locked(self, session_id: UUID) -> SessionSnapshot | None:
        assert self._conn is not None  # noqa: S101
        cur = self._conn.execute(
            """
            SELECT source_ip, username, fake_hostname, fake_username, fake_cwd,
                   started_at, last_activity_at, persona
            FROM sessions WHERE session_id = ?
            """,
            (str(session_id),),
        )
        row = cur.fetchone()
        if row is None:
            return None
        turns = self._fetch_turns(session_id)
        return SessionSnapshot(
            session_id=session_id,
            source_ip=row[0],
            username=row[1],
            fake_hostname=row[2],
            fake_username=row[3],
            fake_cwd=row[4],
            started_at=datetime.fromisoformat(row[5]),
            last_activity_at=datetime.fromisoformat(row[6]),
            turns=turns,
            persona_name=row[7],
        )

    async def get_active_sessions(self, *, limit: int | None = None) -> list[SessionSnapshot]:
        """Return non-ended sessions, newest activity first. Bounded by config."""
        self._require_open()
        effective = limit if limit is not None else self._config.max_active_sessions_returned
        if effective <= 0:
            raise ValueError(f"limit must be positive, got {effective}")
        async with self._lock:
            return await asyncio.to_thread(self._get_active_sessions_locked, effective)

    def _get_active_sessions_locked(self, limit: int) -> list[SessionSnapshot]:
        assert self._conn is not None  # noqa: S101
        cur = self._conn.execute(
            """
            SELECT session_id, source_ip, username, fake_hostname, fake_username,
                   fake_cwd, started_at, last_activity_at, persona
            FROM sessions WHERE ended_at IS NULL
            ORDER BY last_activity_at DESC
            LIMIT ?
            """,
            (limit,),
        )
        return [self._row_to_snapshot_with_turns(row) for row in cur.fetchall()]

    async def get_sessions_in_range(
        self,
        *,
        start: datetime,
        end: datetime,
        limit: int = 10_000,
    ) -> list[SessionSnapshot]:
        """Date-range query used by the Stage 3 export endpoint.

        ``start`` and ``end`` are inclusive bounds on
        ``started_at``. ``limit`` caps the result set; oversize
        requests raise ``ValueError`` so callers (the export
        endpoint with its 7-day window cap) cannot accidentally
        ask for the entire DB.
        """
        self._require_open()
        if limit <= 0 or limit > 10_000:
            raise ValueError(f"limit must be in 1..10_000, got {limit}")
        if end < start:
            raise ValueError("end must be >= start")
        async with self._lock:
            return await asyncio.to_thread(
                self._get_sessions_in_range_locked,
                start,
                end,
                limit,
            )

    def _get_sessions_in_range_locked(
        self,
        start: datetime,
        end: datetime,
        limit: int,
    ) -> list[SessionSnapshot]:
        assert self._conn is not None  # noqa: S101
        cur = self._conn.execute(
            """
            SELECT session_id, source_ip, username, fake_hostname, fake_username,
                   fake_cwd, started_at, last_activity_at, persona
            FROM sessions
            WHERE started_at >= ? AND started_at <= ?
            ORDER BY started_at DESC
            LIMIT ?
            """,
            (start.isoformat(), end.isoformat(), limit),
        )
        return [self._row_to_snapshot_with_turns(row) for row in cur.fetchall()]

    async def get_recent_commands(
        self,
        *,
        limit: int = 100,
    ) -> list[tuple[UUID, CommandTurn]]:
        """Cross-session command stream, newest first."""
        self._require_open()
        if limit <= 0:
            raise ValueError("limit must be positive")
        async with self._lock:
            return await asyncio.to_thread(self._get_recent_commands_locked, limit)

    def _get_recent_commands_locked(self, limit: int) -> list[tuple[UUID, CommandTurn]]:
        assert self._conn is not None  # noqa: S101
        cur = self._conn.execute(
            """
            SELECT session_id, command, response, source, timestamp, latency_ms
            FROM turns
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        )
        return [
            (
                UUID(row[0]),
                CommandTurn(
                    command=row[1],
                    response=row[2],
                    source=ResponseSource(row[3]),
                    timestamp=datetime.fromisoformat(row[4]),
                    latency_ms=row[5],
                ),
            )
            for row in cur.fetchall()
        ]

    async def get_intent(self, session_id: UUID) -> IntentSummary | None:
        """Return the persisted :class:`IntentSummary` or :data:`None`."""
        self._require_open()
        async with self._lock:
            return await asyncio.to_thread(self._get_intent_locked, session_id)

    async def get_intents_in_range(
        self,
        *,
        start: datetime,
        end: datetime,
    ) -> list[IntentSummary]:
        """Return intents with ``extracted_at`` in ``[start, end]``, newest first."""
        self._require_open()
        async with self._lock:
            return await asyncio.to_thread(
                self._get_intents_in_range_locked,
                start,
                end,
            )

    def _get_intents_in_range_locked(
        self,
        start: datetime,
        end: datetime,
    ) -> list[IntentSummary]:
        assert self._conn is not None  # noqa: S101
        rows = self._conn.execute(
            """
            SELECT session_id, actor_profile, intent, why,
                   matched_techniques_json, confidence, summary, extracted_at
            FROM intents
            WHERE extracted_at >= ? AND extracted_at <= ?
            ORDER BY extracted_at DESC
            """,
            (start.isoformat(), end.isoformat()),
        ).fetchall()
        out: list[IntentSummary] = []
        for row in rows:
            techniques_raw = json.loads(row[4]) if row[4] else []
            techniques = tuple(t for t in techniques_raw if isinstance(t, str))
            out.append(
                IntentSummary(
                    session_id=UUID(row[0]),
                    actor_profile=row[1],
                    intent=row[2],
                    why=row[3],
                    matched_techniques=techniques,
                    confidence=row[5],
                    summary=row[6],
                    extracted_at=datetime.fromisoformat(row[7]),
                ),
            )
        return out

    def _get_intent_locked(self, session_id: UUID) -> IntentSummary | None:
        assert self._conn is not None  # noqa: S101
        row = self._conn.execute(
            """
            SELECT actor_profile, intent, why, matched_techniques_json,
                   confidence, summary, extracted_at
            FROM intents
            WHERE session_id = ?
            """,
            (str(session_id),),
        ).fetchone()
        if row is None:
            return None
        techniques_raw = json.loads(row[3]) if row[3] else []
        techniques = tuple(t for t in techniques_raw if isinstance(t, str))
        return IntentSummary(
            session_id=session_id,
            actor_profile=row[0],
            intent=row[1],
            why=row[2],
            matched_techniques=techniques,
            confidence=row[4],
            summary=row[5],
            extracted_at=datetime.fromisoformat(row[6]),
        )

    # ------------------------------------------------------------------
    # Honeytokens (Stage 11 slice 11.2)
    # ------------------------------------------------------------------

    async def register_honeytoken(self, token: Honeytoken) -> bool:
        """Insert a :class:`Honeytoken` into the registry.

        Returns True iff a new row was inserted; False on the
        already-present-via-PK idempotent path (the audit-tailer
        replays the same audit line after offset-cache loss; the
        UNIQUE PK on id makes that safe).

        No FK to sessions: honeytokens outlive their generating
        session. The callback receiver looks tokens up by ``id``;
        the bridge looks them up by ``source_ip`` at session-open
        to seed the lure overlay.
        """
        self._require_open()
        async with self._lock:
            return await asyncio.to_thread(self._register_honeytoken_locked, token)

    def _register_honeytoken_locked(self, token: Honeytoken) -> bool:
        assert self._conn is not None  # noqa: S101
        cur = self._conn.execute(
            """
            INSERT OR IGNORE INTO honeytokens (
                id, kind, payload, callback_url, placed_at,
                source_ip, session_id, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                token.id,
                token.kind,
                token.payload,
                token.callback_url,
                token.placed_at,
                token.source_ip,
                str(token.session_id) if token.session_id is not None else None,
                token.created_at.isoformat(),
            ),
        )
        return cur.rowcount > 0

    async def get_honeytoken(self, token_id: str) -> Honeytoken | None:
        """Look up one honeytoken by its 16-char base32 id.

        Used by the slice 11.4 callback receiver: extract the 16
        chars from incoming requests, query, audit
        bridge.honeytoken_callback on hit, return generic 403
        on miss (no information leak about which IDs exist).
        """
        self._require_open()
        async with self._lock:
            return await asyncio.to_thread(self._get_honeytoken_locked, token_id)

    def _get_honeytoken_locked(self, token_id: str) -> Honeytoken | None:
        assert self._conn is not None  # noqa: S101
        cur = self._conn.execute(
            """
            SELECT id, kind, payload, callback_url, placed_at,
                   source_ip, session_id, created_at
            FROM honeytokens WHERE id = ?
            """,
            (token_id,),
        )
        row = cur.fetchone()
        return _row_to_honeytoken(row) if row is not None else None

    async def list_honeytokens_for_source_ip(
        self,
        source_ip: str,
    ) -> list[Honeytoken]:
        """Return per-session honeytokens generated for ``source_ip``.

        Excludes static-base tokens (those have ``source_ip IS NULL``)
        - the bridge merges those separately into every session's
        overlay. This query feeds the slice 11.3 session-open
        seeding.
        """
        self._require_open()
        async with self._lock:
            return await asyncio.to_thread(
                self._list_honeytokens_locked,
                source_ip,
            )

    def _list_honeytokens_locked(self, source_ip: str) -> list[Honeytoken]:
        assert self._conn is not None  # noqa: S101
        cur = self._conn.execute(
            """
            SELECT id, kind, payload, callback_url, placed_at,
                   source_ip, session_id, created_at
            FROM honeytokens
            WHERE source_ip = ?
            ORDER BY created_at ASC, id ASC
            """,
            (source_ip,),
        )
        return [_row_to_honeytoken(row) for row in cur.fetchall()]

    async def list_static_honeytokens(self) -> list[Honeytoken]:
        """Return the operator-defined static-base tokens (source_ip IS NULL).

        Shipped to every session via the bridge's session-open
        overlay merge alongside any per-source-IP rows.
        """
        self._require_open()
        async with self._lock:
            return await asyncio.to_thread(self._list_static_honeytokens_locked)

    def _list_static_honeytokens_locked(self) -> list[Honeytoken]:
        assert self._conn is not None  # noqa: S101
        cur = self._conn.execute(
            """
            SELECT id, kind, payload, callback_url, placed_at,
                   source_ip, session_id, created_at
            FROM honeytokens
            WHERE source_ip IS NULL
            ORDER BY created_at ASC, id ASC
            """,
        )
        return [_row_to_honeytoken(row) for row in cur.fetchall()]

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
        """Append a :class:`PersistenceEvent` to ``fake_persistence_state``.

        Returns True iff a new row was inserted; False when the
        UNIQUE(source_ip, kind, sub_key, created_at) constraint
        rejected the insert as a replay of an already-persisted
        audit line. Operators can use the return value to
        instrument tailer-replay diagnostics; the caller's normal
        path treats both outcomes the same.

        No FK to sessions: persistence state outlives the session
        that created it. Re-installing the same backdoor at a
        later time produces a second row (different created_at).
        """
        self._require_open()
        async with self._lock:
            return await asyncio.to_thread(
                self._record_persistence_event_locked,
                event,
                source_ip,
                session_id,
                created_at,
            )

    def _record_persistence_event_locked(
        self,
        event: PersistenceEvent,
        source_ip: str,
        session_id: UUID,
        created_at: datetime,
    ) -> bool:
        assert self._conn is not None  # noqa: S101
        cur = self._conn.execute(
            """
            INSERT OR IGNORE INTO fake_persistence_state (
                source_ip, kind, sub_key, payload, source, created_at, session_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                source_ip,
                event.kind,
                event.sub_key,
                event.payload,
                event.source,
                created_at.isoformat(),
                str(session_id),
            ),
        )
        return cur.rowcount > 0

    async def list_persistence_events_for_source_ip(
        self,
        source_ip: str,
    ) -> list[PersistenceEvent]:
        """Return every persistence event for ``source_ip``, oldest first.

        The lure overlay applies path-keyed events in chronological
        order so later authorized_keys appends accumulate on top of
        earlier ones; the bridge fs_context block lists every
        installed crontab line / systemd unit for the LLM to render
        consistently.
        """
        self._require_open()
        async with self._lock:
            return await asyncio.to_thread(
                self._list_persistence_events_locked,
                source_ip,
            )

    def _list_persistence_events_locked(
        self,
        source_ip: str,
    ) -> list[PersistenceEvent]:
        assert self._conn is not None  # noqa: S101
        cur = self._conn.execute(
            """
            SELECT kind, sub_key, payload, source
            FROM fake_persistence_state
            WHERE source_ip = ?
            ORDER BY created_at ASC, id ASC
            """,
            (source_ip,),
        )
        return [
            PersistenceEvent(
                kind=row[0],
                sub_key=row[1],
                payload=row[2],
                source=row[3],
            )
            for row in cur.fetchall()
        ]

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
        """Pin ``source_ip`` to ``persona``; returns the persisted record.

        INSERT OR REPLACE on source_ip so pinning the same IP twice
        overwrites with a fresh created_at. The bridge's
        :class:`SessionStoreReader.get_persona_pin` reads what
        this writes.
        """
        self._require_open()
        async with self._lock:
            return await asyncio.to_thread(
                self._upsert_persona_pin_locked,
                source_ip,
                persona,
                created_by,
            )

    def _upsert_persona_pin_locked(
        self,
        source_ip: str,
        persona: str,
        created_by: str,
    ) -> PersonaPin:
        assert self._conn is not None  # noqa: S101
        created_at = datetime.now(tz=UTC)
        self._conn.execute(
            """
            INSERT INTO persona_pins (source_ip, persona, created_at, created_by)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(source_ip) DO UPDATE SET
                persona    = excluded.persona,
                created_at = excluded.created_at,
                created_by = excluded.created_by
            """,
            (source_ip, persona, created_at.isoformat(), created_by),
        )
        return PersonaPin(
            source_ip=source_ip,
            persona=persona,
            created_at=created_at,
            created_by=created_by,
        )

    async def list_persona_pins(self) -> list[PersonaPin]:
        """Return every active pin, newest first."""
        self._require_open()
        async with self._lock:
            return await asyncio.to_thread(self._list_persona_pins_locked)

    def _list_persona_pins_locked(self) -> list[PersonaPin]:
        assert self._conn is not None  # noqa: S101
        cur = self._conn.execute(
            """
            SELECT source_ip, persona, created_at, created_by
            FROM persona_pins
            ORDER BY created_at DESC
            """,
        )
        return [
            PersonaPin(
                source_ip=row[0],
                persona=row[1],
                created_at=datetime.fromisoformat(row[2]),
                created_by=row[3],
            )
            for row in cur.fetchall()
        ]

    async def delete_persona_pin(self, source_ip: str) -> bool:
        """Remove ``source_ip``'s pin if present. Returns True iff a row was deleted."""
        self._require_open()
        async with self._lock:
            return await asyncio.to_thread(self._delete_persona_pin_locked, source_ip)

    def _delete_persona_pin_locked(self, source_ip: str) -> bool:
        assert self._conn is not None  # noqa: S101
        cur = self._conn.execute(
            "DELETE FROM persona_pins WHERE source_ip = ?",
            (source_ip,),
        )
        return cur.rowcount > 0

    async def update_session_persona(
        self,
        session_id: UUID,
        persona: str,
    ) -> bool:
        """Set the persona on an existing session row. Returns True iff updated.

        Used by the dashboard tailer's cluster-bias rebound path
        (slice 9.4): when a freshly closed session's embedding has a
        strong neighbour with a different persona, the tailer
        rewrites the just-closed session's persona so the selector's
        recurrence query picks up the rebound on the next session-
        open from this source IP.
        """
        self._require_open()
        async with self._lock:
            return await asyncio.to_thread(
                self._update_session_persona_locked,
                session_id,
                persona,
            )

    def _update_session_persona_locked(self, session_id: UUID, persona: str) -> bool:
        assert self._conn is not None  # noqa: S101
        cur = self._conn.execute(
            "UPDATE sessions SET persona = ? WHERE session_id = ?",
            (persona, str(session_id)),
        )
        return cur.rowcount > 0

    # ------------------------------------------------------------------
    # Embeddings (Stage 8)
    # ------------------------------------------------------------------

    async def upsert_embedding(self, embedding: SessionEmbedding) -> None:
        """Persist a :class:`SessionEmbedding` keyed by ``session_id``.

        FK to the ``sessions`` row is enforced (cascade-delete);
        callers must have already persisted the session itself.
        Repeated calls for the same session_id overwrite the row.
        """
        self._require_open()
        async with self._lock:
            await asyncio.to_thread(self._upsert_embedding_locked, embedding)

    def _upsert_embedding_locked(self, embedding: SessionEmbedding) -> None:
        assert self._conn is not None  # noqa: S101
        blob = _pack_vector(embedding.vector)
        self._conn.execute(
            """
            INSERT INTO embeddings (
                session_id, vector_blob, dimension, model, generated_at
            ) VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(session_id) DO UPDATE SET
                vector_blob  = excluded.vector_blob,
                dimension    = excluded.dimension,
                model        = excluded.model,
                generated_at = excluded.generated_at
            """,
            (
                str(embedding.session_id),
                blob,
                embedding.dimension,
                embedding.model,
                embedding.generated_at.isoformat(),
            ),
        )

    async def get_embedding(self, session_id: UUID) -> SessionEmbedding | None:
        """Return the persisted :class:`SessionEmbedding` or :data:`None`."""
        self._require_open()
        async with self._lock:
            return await asyncio.to_thread(self._get_embedding_locked, session_id)

    def _get_embedding_locked(self, session_id: UUID) -> SessionEmbedding | None:
        assert self._conn is not None  # noqa: S101
        row = self._conn.execute(
            """
            SELECT vector_blob, dimension, model, generated_at
            FROM embeddings
            WHERE session_id = ?
            """,
            (str(session_id),),
        ).fetchone()
        if row is None:
            return None
        return _row_to_embedding(session_id, row)

    async def find_similar(
        self,
        session_id: UUID,
        *,
        k: int = 5,
        min_similarity: float = 0.85,
    ) -> list[tuple[SessionEmbedding, float]]:
        """Return up to ``k`` neighbours of ``session_id`` above the threshold.

        Linear scan over every stored vector with the SAME model tag
        (cross-model comparisons are silently excluded; vectors from
        different embed models live in different spaces). The query
        vector itself is excluded from the result. Tuples are
        returned newest-first by cosine similarity. Returns an empty
        list if the query session has no stored embedding.
        """
        self._require_open()
        if k <= 0:
            raise ValueError("k must be positive")
        if not 0.0 <= min_similarity <= 1.0:
            raise ValueError("min_similarity must be in [0, 1]")
        async with self._lock:
            return await asyncio.to_thread(
                self._find_similar_locked,
                session_id,
                k,
                min_similarity,
            )

    def _find_similar_locked(
        self,
        session_id: UUID,
        k: int,
        min_similarity: float,
    ) -> list[tuple[SessionEmbedding, float]]:
        assert self._conn is not None  # noqa: S101
        query_row = self._conn.execute(
            "SELECT vector_blob, dimension, model FROM embeddings WHERE session_id = ?",
            (str(session_id),),
        ).fetchone()
        if query_row is None:
            return []
        query_vec = _unpack_vector(query_row[0], query_row[1])
        query_model = query_row[2]
        # Filter on model so we never compare across embedding spaces.
        rows = self._conn.execute(
            """
            SELECT session_id, vector_blob, dimension, model, generated_at
            FROM embeddings
            WHERE model = ? AND session_id != ?
            """,
            (query_model, str(session_id)),
        ).fetchall()
        scored: list[tuple[SessionEmbedding, float]] = []
        for row in rows:
            other_vec = _unpack_vector(row[1], row[2])
            sim = _cosine_similarity(query_vec, other_vec)
            if sim >= min_similarity:
                scored.append((_row_to_embedding(UUID(row[0]), row[1:5]), sim))
        scored.sort(key=lambda pair: pair[1], reverse=True)
        return scored[:k]

    async def get_recent_threats(self, *, limit: int = 50) -> list[ThreatAssessment]:
        """Most-recently-updated threat assessments, newest first."""
        self._require_open()
        if limit <= 0:
            raise ValueError("limit must be positive")
        async with self._lock:
            return await asyncio.to_thread(self._get_recent_threats_locked, limit)

    def _get_recent_threats_locked(self, limit: int) -> list[ThreatAssessment]:
        assert self._conn is not None  # noqa: S101
        cur = self._conn.execute(
            """
            SELECT session_id, score, persistence_attempted, high_severity,
                   techniques_json, notes_json
            FROM threats
            ORDER BY last_updated_at DESC
            LIMIT ?
            """,
            (limit,),
        )
        out: list[ThreatAssessment] = []
        for row in cur.fetchall():
            techniques_raw = json.loads(row[4]) if row[4] else []
            techniques = tuple(
                ThreatTechnique(
                    id=t["id"],
                    name=t["name"],
                    matches=tuple(t.get("matches") or ()),
                )
                for t in techniques_raw
            )
            notes_raw = json.loads(row[5]) if row[5] else []
            out.append(
                ThreatAssessment(
                    session_id=UUID(row[0]),
                    score=int(row[1]),
                    persistence_attempted=bool(row[2]),
                    high_severity=bool(row[3]),
                    techniques=techniques,
                    notes=tuple(notes_raw),
                ),
            )
        return out

    async def get_stats(self) -> SessionStoreStats:
        """One-shot aggregate used by ``/api/stats`` and the health panel."""
        self._require_open()
        async with self._lock:
            return await asyncio.to_thread(self._get_stats_locked)

    def _get_stats_locked(self) -> SessionStoreStats:
        assert self._conn is not None  # noqa: S101
        active = self._scalar("SELECT COUNT(*) FROM sessions WHERE ended_at IS NULL")
        commands = self._scalar("SELECT COUNT(*) FROM turns")
        threats = self._scalar("SELECT COUNT(*) FROM threats")
        high_sev = self._scalar("SELECT COUNT(*) FROM threats WHERE high_severity = 1")
        persistence = self._scalar(
            "SELECT COUNT(*) FROM threats WHERE persistence_attempted = 1",
        )
        return SessionStoreStats(
            active_sessions=active,
            total_commands_observed=commands,
            total_threat_assessments=threats,
            high_severity_count=high_sev,
            persistence_attempt_count=persistence,
        )

    # -----------------------------------------------------------------
    # Internals
    # -----------------------------------------------------------------

    def _require_open(self) -> None:
        if self._conn is None:
            raise RuntimeError("SessionStore.open() must be awaited first")

    def _scalar(self, sql: str, params: Sequence[Any] = ()) -> int:
        assert self._conn is not None  # noqa: S101
        cur = self._conn.execute(sql, params)
        row = cur.fetchone()
        if row is None or row[0] is None:
            return 0
        value = row[0]
        if not isinstance(value, (int, float)):
            # Closed in pre-deploy sweep (TODO-6): the previous
            # ``else 0`` silently coerced non-numeric values, masking
            # schema corruption or a query that gained a non-numeric
            # column without updating the caller. The helper is only
            # used internally for COUNT/SUM scalars; a non-numeric
            # result is always a programming error.
            raise TypeError(
                f"_scalar expected numeric result, got {type(value).__name__} from SQL: {sql!r}",
            )
        return int(value)

    def _fetch_turns(self, session_id: UUID) -> tuple[CommandTurn, ...]:
        assert self._conn is not None  # noqa: S101
        cur = self._conn.execute(
            """
            SELECT command, response, source, timestamp, latency_ms
            FROM turns WHERE session_id = ? ORDER BY sequence_n ASC
            """,
            (str(session_id),),
        )
        return tuple(
            CommandTurn(
                command=row[0],
                response=row[1],
                source=ResponseSource(row[2]),
                timestamp=datetime.fromisoformat(row[3]),
                latency_ms=row[4],
            )
            for row in cur.fetchall()
        )

    def _row_to_snapshot_with_turns(self, row: Sequence[Any]) -> SessionSnapshot:
        session_id = UUID(row[0])
        return SessionSnapshot(
            session_id=session_id,
            source_ip=row[1],
            username=row[2],
            fake_hostname=row[3],
            fake_username=row[4],
            fake_cwd=row[5],
            started_at=datetime.fromisoformat(row[6]),
            last_activity_at=datetime.fromisoformat(row[7]),
            turns=self._fetch_turns(session_id),
            persona_name=row[8] if len(row) > 8 else None,
        )


def _utcnow_iso() -> str:
    return datetime.now(tz=UTC).isoformat()


# ---------------------------------------------------------------------------
# Honeytoken row hydration (Stage 11 slice 11.2)
# ---------------------------------------------------------------------------


def _row_to_honeytoken(row: Sequence[Any]) -> Honeytoken:
    """Rehydrate one honeytokens row into a :class:`Honeytoken`.

    Row column order matches the SELECT in
    :meth:`SessionStore._get_honeytoken_locked` /
    :meth:`SessionStore._list_honeytokens_locked`.
    """
    session_id_raw = row[6]
    return Honeytoken(
        id=row[0],
        kind=row[1],
        payload=row[2],
        callback_url=row[3],
        placed_at=row[4],
        source_ip=row[5],
        session_id=UUID(session_id_raw) if session_id_raw is not None else None,
        created_at=datetime.fromisoformat(row[7]),
    )


# ---------------------------------------------------------------------------
# Embedding helpers (Stage 8 slice 3)
# ---------------------------------------------------------------------------


def _pack_vector(vector: Sequence[float]) -> bytes:
    """Pack a vector as little-endian float32 bytes (4 bytes per element).

    Float32 is enough precision for cosine similarity over 768-1024-
    dim embedding vectors; halving the byte footprint vs float64 keeps
    the audit-log + DB write costs proportional. Little-endian is the
    SQLite convention and matches every x86_64 host Anglerfish runs on.
    """
    return struct.pack(f"<{len(vector)}f", *vector)


def _unpack_vector(blob: bytes, dimension: int) -> tuple[float, ...]:
    """Unpack a float32 blob into a tuple of floats.

    Raises :class:`ValueError` if the blob length does not match
    ``dimension * 4``; the row is then corrupted and the caller drops
    it.
    """
    expected_bytes = dimension * 4
    if len(blob) != expected_bytes:
        raise ValueError(
            f"vector blob length {len(blob)} does not match dimension "
            f"{dimension} (expected {expected_bytes} bytes)",
        )
    return tuple(struct.unpack(f"<{dimension}f", blob))


def _row_to_embedding(session_id: UUID, row: Sequence[Any]) -> SessionEmbedding:
    """Build a :class:`SessionEmbedding` from a query row.

    ``row`` is expected to contain ``(vector_blob, dimension, model,
    generated_at)`` in that order. Used by both get_embedding and
    find_similar (which slices its own row tuple to that shape).
    """
    vector = _unpack_vector(row[0], row[1])
    return SessionEmbedding(
        session_id=session_id,
        vector=vector,
        dimension=row[1],
        model=row[2],
        generated_at=datetime.fromisoformat(row[3]),
    )


def _cosine_similarity(a: Sequence[float], b: Sequence[float]) -> float:
    """Cosine similarity between two equal-length vectors.

    Returns 0.0 when either vector is the zero vector. Caller filters
    on a configurable threshold afterwards.
    """
    if len(a) != len(b):
        raise ValueError(
            f"cosine similarity requires equal-length vectors, got {len(a)} and {len(b)}",
        )
    dot = 0.0
    a_norm_sq = 0.0
    b_norm_sq = 0.0
    for av, bv in zip(a, b, strict=True):
        dot += av * bv
        a_norm_sq += av * av
        b_norm_sq += bv * bv
    if not a_norm_sq or not b_norm_sq:
        # Zero-norm vectors have no defined cosine; treat as no match.
        return 0.0
    return dot / (math.sqrt(a_norm_sq) * math.sqrt(b_norm_sq))
