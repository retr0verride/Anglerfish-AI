"""Read-only :class:`SessionStore` facade for the bridge process.

The bridge process today does not touch the sessions database; the
dashboard process owns writes via the audit tailer. Stage 9 needs
a synchronous read at session-open ("what persona did this source
IP get last time?") and the persona-pin lookup ("did the operator
pin this IP to a specific persona?"). Opening a second writer
connection in the bridge would create dual-writer hazards; opening
a read-only connection over the same WAL-mode file is the
SQLite-idiomatic answer.

This module exposes only the selector queries. Adding a method
here is a deliberate widening of the cross-process surface; keep
the API minimal.
"""

from __future__ import annotations

import asyncio
import logging
import sqlite3
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Self
from uuid import UUID

from anglerfish.honeytokens.schema import Honeytoken
from anglerfish.models.persistence import PersistenceEvent
from anglerfish.sessions.schema import PRAGMAS

if TYPE_CHECKING:
    from anglerfish.config.models import SessionStoreConfig

__all__ = ["SessionStoreReader"]


_logger = logging.getLogger(__name__)


class SessionStoreReader:
    """Read-only handle on the session store, scoped to selector queries.

    Construct once at bridge startup and share for the lifetime of
    the process. Lookups are dispatched through
    :func:`asyncio.to_thread` so they do not block the event loop;
    a single ``asyncio.Lock`` serialises access to the underlying
    sqlite3 connection (which is not thread-safe by default).
    """

    def __init__(self, config: SessionStoreConfig) -> None:
        self._config = config
        self._conn: sqlite3.Connection | None = None
        self._lock = asyncio.Lock()

    @property
    def is_open(self) -> bool:
        return self._conn is not None

    async def open(self) -> None:
        """Open the database file in read-only mode. Idempotent."""
        async with self._lock:
            if self._conn is not None:
                return
            await asyncio.to_thread(self._open_locked)

    def _open_locked(self) -> None:
        path = self._config.database_path
        if not path.exists():
            # The dashboard process owns DB creation; if the bridge
            # starts first the file may not exist yet. Opening a
            # missing read-only URI raises a clear error rather than
            # silently materialising an empty DB.
            raise FileNotFoundError(
                f"SessionStoreReader: database file not found at {path}; "
                "the dashboard process must create it before the bridge starts",
            )
        uri = f"file:{path}?mode=ro"
        conn = sqlite3.connect(
            uri,
            uri=True,
            isolation_level=None,
            check_same_thread=False,
        )
        try:
            for pragma in PRAGMAS:
                # journal_mode + synchronous are no-ops on a read-only
                # handle; foreign_keys still applies to queries. Apply
                # the same set for parity with SessionStore so a future
                # pragma addition lands here automatically.
                conn.execute(pragma)
        except sqlite3.Error:
            conn.close()
            raise
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
    # Selector queries
    # -----------------------------------------------------------------

    async def recent_persona_for_source_ip(self, source_ip: str) -> str | None:
        """Most recent persona assigned to this source IP, or None.

        The selector's "source-IP recurrence" rule. Filters
        ``WHERE persona IS NOT NULL`` so pre-Stage-9 rows (which
        have a NULL persona column) do not bias selection.
        Returns ``None`` when no prior session matches.
        """
        self._require_open()
        async with self._lock:
            return await asyncio.to_thread(
                self._recent_persona_for_source_ip_locked,
                source_ip,
            )

    def _recent_persona_for_source_ip_locked(self, source_ip: str) -> str | None:
        assert self._conn is not None  # noqa: S101
        cur = self._conn.execute(
            """
            SELECT persona
            FROM sessions
            WHERE source_ip = ? AND persona IS NOT NULL
            ORDER BY started_at DESC
            LIMIT 1
            """,
            (source_ip,),
        )
        row = cur.fetchone()
        return row[0] if row is not None else None

    async def get_persona_pin(self, source_ip: str) -> str | None:
        """Return the operator-pinned persona for this IP, or None."""
        self._require_open()
        async with self._lock:
            return await asyncio.to_thread(self._get_persona_pin_locked, source_ip)

    def _get_persona_pin_locked(self, source_ip: str) -> str | None:
        assert self._conn is not None  # noqa: S101
        cur = self._conn.execute(
            "SELECT persona FROM persona_pins WHERE source_ip = ?",
            (source_ip,),
        )
        row = cur.fetchone()
        return row[0] if row is not None else None

    async def get_counter_deception_pin(self, source_ip: str) -> str | None:
        """Return the operator-pinned counter-deception mode for this IP, or None.

        The bridge reads this at session-open (Stage 12). A returned
        value is one of the :class:`CounterDeceptionMode` string values
        (``off`` / ``garble`` / ``timebomb`` / ``both``); the caller
        maps it back to the enum. ``None`` means no pin (fall through to
        the threat-driven engagement path).
        """
        self._require_open()
        async with self._lock:
            return await asyncio.to_thread(self._get_counter_deception_pin_locked, source_ip)

    def _get_counter_deception_pin_locked(self, source_ip: str) -> str | None:
        assert self._conn is not None  # noqa: S101
        cur = self._conn.execute(
            "SELECT mode FROM counter_deception_pins WHERE source_ip = ?",
            (source_ip,),
        )
        row = cur.fetchone()
        return row[0] if row is not None else None

    async def list_persistence_for_source_ip(
        self,
        source_ip: str,
    ) -> list[PersistenceEvent]:
        """Stage 10: prior-session persistence events for ``source_ip``.

        Oldest first. Used by the bridge at session-open to seed
        SessionContext.persistence_events so the prompt builder's
        Stage 10 block reflects cross-session installs immediately
        on the new session's first command.
        """
        self._require_open()
        async with self._lock:
            return await asyncio.to_thread(
                self._list_persistence_for_source_ip_locked,
                source_ip,
            )

    def _list_persistence_for_source_ip_locked(
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

    async def get_honeytoken(self, token_id: str) -> Honeytoken | None:
        """Stage 11: callback-receiver lookup by 16-char base32 id.

        Returns :data:`None` for unknown token_ids (the callback
        receiver still serves a generic 403 to avoid leaking
        which IDs exist).
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
        """Stage 11: per-session honeytokens for the bridge session-open seed.

        Oldest first. Excludes static-base tokens (those have
        ``source_ip IS NULL``); slice 11.3's bridge integration
        merges static + per-IP rows separately into the lure
        ``fakefs_overlay``.
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
        """Stage 11: operator-defined static-base tokens (source_ip IS NULL)."""
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

    # -----------------------------------------------------------------
    # Internals
    # -----------------------------------------------------------------

    def _require_open(self) -> None:
        if self._conn is None:
            raise RuntimeError("SessionStoreReader.open() must be awaited first")


def _utcnow() -> datetime:  # pragma: no cover - reserved for future writers
    return datetime.now(tz=UTC)


def _row_to_honeytoken(row: tuple[object, ...]) -> Honeytoken:
    """Rehydrate one honeytokens row into a :class:`Honeytoken`.

    Mirrors :func:`anglerfish.sessions.store._row_to_honeytoken`;
    duplicated here so the reader has no import dependency on the
    writer module. The two helpers stay in lock-step because they
    SELECT the same column order.
    """
    session_id_raw = row[6]
    return Honeytoken(
        id=str(row[0]),
        kind=str(row[1]),  # type: ignore[arg-type]
        payload=str(row[2]),
        callback_url=str(row[3]),
        placed_at=str(row[4]),
        source_ip=str(row[5]) if row[5] is not None else None,
        session_id=UUID(str(session_id_raw)) if session_id_raw is not None else None,
        created_at=datetime.fromisoformat(str(row[7])),
    )
