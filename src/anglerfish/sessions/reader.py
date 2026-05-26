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

    # -----------------------------------------------------------------
    # Internals
    # -----------------------------------------------------------------

    def _require_open(self) -> None:
        if self._conn is None:
            raise RuntimeError("SessionStoreReader.open() must be awaited first")


def _utcnow() -> datetime:  # pragma: no cover - reserved for future writers
    return datetime.now(tz=UTC)
