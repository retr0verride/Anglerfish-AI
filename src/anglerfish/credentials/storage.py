"""Credential intelligence database (SQLite + AES-GCM).

Each ``(source_ip, username, password)`` tuple is stored once.
Repeated attempts of the same tuple update the row's ``last_seen``
and increment its ``attempt_count``. Deduplication uses HMAC
fingerprints so the index lookups never have to decrypt rows.

The database file is created with mode ``0o600`` — encrypted at rest
is necessary but not sufficient; on-disk permissions matter too.
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import sqlite3
from collections.abc import Sequence
from datetime import datetime
from typing import Any, Self
from uuid import UUID

from anglerfish.config.models import CredentialsConfig
from anglerfish.credentials.crypto import CredentialCipher
from anglerfish.models.credentials import CredentialRecord, CredentialStats

__all__ = ["CredentialStore"]


_SCHEMA = """
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS attempts (
    id              INTEGER PRIMARY KEY,
    source_ip       TEXT NOT NULL,
    session_id      TEXT NOT NULL,
    username_ct     BLOB NOT NULL,
    username_nonce  BLOB NOT NULL,
    password_ct     BLOB NOT NULL,
    password_nonce  BLOB NOT NULL,
    username_fp     BLOB NOT NULL,
    password_fp     BLOB NOT NULL,
    first_seen      TEXT NOT NULL,
    last_seen       TEXT NOT NULL,
    attempt_count   INTEGER NOT NULL DEFAULT 1
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_attempts_unique
    ON attempts(source_ip, username_fp, password_fp);
CREATE INDEX IF NOT EXISTS idx_attempts_last_seen ON attempts(last_seen);
CREATE INDEX IF NOT EXISTS idx_attempts_source_ip ON attempts(source_ip);
"""


class CredentialStore:
    """SQLite-backed encrypted credential intelligence database."""

    def __init__(
        self,
        config: CredentialsConfig,
        *,
        cipher: CredentialCipher | None = None,
    ) -> None:
        self._config = config
        self._cipher = (
            cipher
            if cipher is not None
            else CredentialCipher(config.encryption_key.get_secret_value())
        )
        self._conn: sqlite3.Connection | None = None
        self._lock = asyncio.Lock()

    @property
    def config(self) -> CredentialsConfig:
        return self._config

    @property
    def cipher(self) -> CredentialCipher:
        return self._cipher

    @property
    def is_open(self) -> bool:
        return self._conn is not None

    async def open(self) -> None:
        """Open the database (creating it if necessary) and run migrations."""
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
            isolation_level=None,
            check_same_thread=False,
        )
        try:
            conn.executescript(_SCHEMA)
        except sqlite3.Error:
            conn.close()
            raise
        if new_file:
            # chmod is a partial no-op on Windows; best-effort, never fatal.
            with contextlib.suppress(OSError):
                os.chmod(path, 0o600)
        self._conn = conn

    async def record_attempt(
        self,
        *,
        source_ip: str,
        username: str,
        password: str,
        session_id: UUID,
        timestamp: datetime,
    ) -> bool:
        """Record one credential attempt.

        Returns:
            True if this is a previously-unseen ``(source_ip, username,
            password)`` triple, False if it is an existing combination
            whose count was incremented.
        """
        if self._conn is None:
            raise RuntimeError("CredentialStore.open() must be awaited first")

        fp_u = self._cipher.fingerprint(username)
        fp_p = self._cipher.fingerprint(password)
        ct_u, nonce_u = self._cipher.encrypt(username)
        ct_p, nonce_p = self._cipher.encrypt(password)
        when = timestamp.isoformat()
        sid = str(session_id)

        async with self._lock:
            return await asyncio.to_thread(
                self._record_attempt_locked,
                source_ip,
                sid,
                ct_u,
                nonce_u,
                ct_p,
                nonce_p,
                fp_u,
                fp_p,
                when,
            )

    def _record_attempt_locked(
        self,
        source_ip: str,
        session_id_str: str,
        ct_u: bytes,
        nonce_u: bytes,
        ct_p: bytes,
        nonce_p: bytes,
        fp_u: bytes,
        fp_p: bytes,
        when_iso: str,
    ) -> bool:
        assert self._conn is not None  # noqa: S101 - invariant, not a runtime check
        cur = self._conn.execute(
            """
            SELECT id, attempt_count
            FROM attempts
            WHERE source_ip = ? AND username_fp = ? AND password_fp = ?
            """,
            (source_ip, fp_u, fp_p),
        )
        row = cur.fetchone()
        if row is None:
            cap = self._config.max_unique_per_source_ip
            if cap > 0:
                count_cur = self._conn.execute(
                    "SELECT COUNT(*) FROM attempts WHERE source_ip = ?",
                    (source_ip,),
                )
                (existing_count,) = count_cur.fetchone()
                if existing_count >= cap:
                    # Cap reached for this source IP. Drop the new unique
                    # attempt to bound disk growth — the per-attempt event
                    # still lands in the audit log via the lure's
                    # lure.login_attempt record, so the operator can still
                    # see what was tried.
                    return False
            self._conn.execute(
                """
                INSERT INTO attempts (
                    source_ip, session_id,
                    username_ct, username_nonce, password_ct, password_nonce,
                    username_fp, password_fp,
                    first_seen, last_seen, attempt_count
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
                """,
                (
                    source_ip,
                    session_id_str,
                    ct_u,
                    nonce_u,
                    ct_p,
                    nonce_p,
                    fp_u,
                    fp_p,
                    when_iso,
                    when_iso,
                ),
            )
            return True

        attempt_id = row[0]
        new_count = row[1] + 1
        self._conn.execute(
            "UPDATE attempts SET last_seen = ?, attempt_count = ? WHERE id = ?",
            (when_iso, new_count, attempt_id),
        )
        return False

    async def query(
        self,
        *,
        limit: int = 100,
        offset: int = 0,
        source_ip: str | None = None,
    ) -> list[CredentialRecord]:
        """Return up to ``limit`` records ordered by most recent ``last_seen``."""
        if self._conn is None:
            raise RuntimeError("CredentialStore.open() must be awaited first")
        if limit <= 0:
            raise ValueError(f"limit must be positive, got {limit}")
        if offset < 0:
            raise ValueError(f"offset must be non-negative, got {offset}")

        async with self._lock:
            rows = await asyncio.to_thread(
                self._query_locked,
                limit,
                offset,
                source_ip,
            )

        records: list[CredentialRecord] = []
        for (
            row_source_ip,
            ct_u,
            nonce_u,
            ct_p,
            nonce_p,
            first_seen,
            last_seen,
            attempt_count,
        ) in rows:
            try:
                username = self._cipher.decrypt(ct_u, nonce_u)
                password = self._cipher.decrypt(ct_p, nonce_p)
            except ValueError:
                continue  # decryption failure means key mismatch — skip safely
            records.append(
                CredentialRecord(
                    source_ip=row_source_ip,
                    username=username,
                    password=password,
                    first_seen=datetime.fromisoformat(first_seen),
                    last_seen=datetime.fromisoformat(last_seen),
                    attempt_count=attempt_count,
                ),
            )
        return records

    def _query_locked(
        self,
        limit: int,
        offset: int,
        source_ip: str | None,
    ) -> Sequence[tuple[Any, ...]]:
        assert self._conn is not None  # noqa: S101
        sql_parts: list[str] = [
            "SELECT source_ip, username_ct, username_nonce, "
            "password_ct, password_nonce, first_seen, last_seen, attempt_count",
            "FROM attempts",
        ]
        params: list[Any] = []
        if source_ip is not None:
            sql_parts.append("WHERE source_ip = ?")
            params.append(source_ip)
        sql_parts.append("ORDER BY last_seen DESC LIMIT ? OFFSET ?")
        params.extend([limit, offset])
        cur = self._conn.execute(" ".join(sql_parts), params)
        return cur.fetchall()

    async def stats(self) -> CredentialStats:
        if self._conn is None:
            raise RuntimeError("CredentialStore.open() must be awaited first")
        async with self._lock:
            data = await asyncio.to_thread(self._stats_locked)
        total, combinations, usernames, passwords, ips = data
        return CredentialStats(
            total_attempts=total,
            unique_combinations=combinations,
            unique_usernames=usernames,
            unique_passwords=passwords,
            unique_source_ips=ips,
        )

    def _stats_locked(self) -> tuple[int, int, int, int, int]:
        assert self._conn is not None  # noqa: S101
        total = self._scalar("SELECT COALESCE(SUM(attempt_count), 0) FROM attempts")
        combinations = self._scalar("SELECT COUNT(*) FROM attempts")
        usernames = self._scalar("SELECT COUNT(DISTINCT username_fp) FROM attempts")
        passwords = self._scalar("SELECT COUNT(DISTINCT password_fp) FROM attempts")
        ips = self._scalar("SELECT COUNT(DISTINCT source_ip) FROM attempts")
        return total, combinations, usernames, passwords, ips

    def _scalar(self, sql: str) -> int:
        assert self._conn is not None  # noqa: S101
        row = self._conn.execute(sql).fetchone()
        if row is None or row[0] is None:
            return 0
        value = row[0]
        return int(value) if isinstance(value, (int, float)) else 0

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
