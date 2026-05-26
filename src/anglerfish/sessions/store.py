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
import os
import sqlite3
from collections.abc import Sequence
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Self
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from anglerfish.models.intent import IntentSummary
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
                fake_cwd, started_at, last_activity_at, ended_at, command_count
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL, ?)
            ON CONFLICT(session_id) DO UPDATE SET
                source_ip        = excluded.source_ip,
                username         = excluded.username,
                fake_hostname    = excluded.fake_hostname,
                fake_username    = excluded.fake_username,
                fake_cwd         = excluded.fake_cwd,
                last_activity_at = excluded.last_activity_at
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
                   started_at, last_activity_at
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
                   fake_cwd, started_at, last_activity_at
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
                   fake_cwd, started_at, last_activity_at
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
        return int(value) if isinstance(value, (int, float)) else 0

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
        )


def _utcnow_iso() -> str:
    return datetime.now(tz=UTC).isoformat()
