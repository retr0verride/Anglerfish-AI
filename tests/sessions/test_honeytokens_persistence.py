"""Stage 11 slice 11.2: ``honeytokens`` table + SessionStore CRUD."""

from __future__ import annotations

import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID, uuid4

from anglerfish.config.models import SessionStoreConfig
from anglerfish.honeytokens.schema import Honeytoken
from anglerfish.sessions import SessionStore
from anglerfish.sessions.reader import SessionStoreReader
from anglerfish.sessions.schema import CURRENT_SCHEMA_VERSION, run_migrations


def _token(
    *,
    token_id: str = "AAAAAAAAAAAAAAAA",  # noqa: S107 - test fixture, not a credential
    kind: str = "aws",
    source_ip: str | None = "203.0.113.7",
    session_id: UUID | None = None,
    placed_at: str = "/root/.aws/credentials",
    when: datetime | None = None,
) -> Honeytoken:
    return Honeytoken(
        id=token_id,
        kind=kind,  # type: ignore[arg-type]
        payload=f"[default]\naws_access_key_id = AKIA{token_id}\n",
        callback_url=f"https://honey.example.com/cb/{token_id}",
        placed_at=placed_at,
        source_ip=source_ip,
        session_id=session_id,
        created_at=when or datetime(2026, 5, 26, 12, 0, tzinfo=UTC),
    )


# ---------------------------------------------------------------------------
# Schema v6 migration
# ---------------------------------------------------------------------------


def test_current_schema_version_at_or_above_six() -> None:
    assert CURRENT_SCHEMA_VERSION >= 6


def test_migration_creates_honeytokens_table(tmp_path: Path) -> None:
    db = tmp_path / "schema.db"
    conn = sqlite3.connect(db)
    try:
        run_migrations(conn)
        rows = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='honeytokens'",
        ).fetchall()
        assert rows == [("honeytokens",)]
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# SessionStore CRUD round-trip
# ---------------------------------------------------------------------------


async def test_register_and_get_honeytoken_round_trip(tmp_path: Path) -> None:
    config = SessionStoreConfig(database_path=tmp_path / "store.db")
    async with SessionStore(config) as store:
        sid = uuid4()
        inserted = await store.register_honeytoken(
            _token(token_id="ABCDEFGHIJKLMNOP", session_id=sid),
        )
        assert inserted is True
        loaded = await store.get_honeytoken("ABCDEFGHIJKLMNOP")
    assert loaded is not None
    assert loaded.id == "ABCDEFGHIJKLMNOP"
    assert loaded.kind == "aws"
    assert loaded.session_id == sid
    assert loaded.source_ip == "203.0.113.7"


async def test_register_honeytoken_replay_is_idempotent(tmp_path: Path) -> None:
    """INSERT OR IGNORE on the PK: re-registering same id returns False."""
    config = SessionStoreConfig(database_path=tmp_path / "store.db")
    async with SessionStore(config) as store:
        first = await store.register_honeytoken(_token())
        replay = await store.register_honeytoken(
            _token(),  # same id; different other fields shouldn't matter
        )
    assert first is True
    assert replay is False


async def test_get_honeytoken_returns_none_for_unknown_id(tmp_path: Path) -> None:
    config = SessionStoreConfig(database_path=tmp_path / "store.db")
    async with SessionStore(config) as store:
        loaded = await store.get_honeytoken("UNKNOWNUNKNOWN77")
    assert loaded is None


async def test_static_base_honeytoken_round_trips_with_nulls(tmp_path: Path) -> None:
    """source_ip=None + session_id=None persist as NULL columns."""
    config = SessionStoreConfig(database_path=tmp_path / "store.db")
    async with SessionStore(config) as store:
        await store.register_honeytoken(
            _token(token_id="STATICAAAAAAAAAA", source_ip=None, session_id=None),
        )
        loaded = await store.get_honeytoken("STATICAAAAAAAAAA")
    assert loaded is not None
    assert loaded.source_ip is None
    assert loaded.session_id is None
    assert loaded.is_static_base()


# ---------------------------------------------------------------------------
# list queries
# ---------------------------------------------------------------------------


async def test_list_honeytokens_for_source_ip_filters_correctly(
    tmp_path: Path,
) -> None:
    config = SessionStoreConfig(database_path=tmp_path / "store.db")
    async with SessionStore(config) as store:
        sid = uuid4()
        # IP 7: one token. IP 8: one token. Static base: one.
        await store.register_honeytoken(
            _token(token_id="AAAAAAAAAAAAAAAA", source_ip="203.0.113.7", session_id=sid),
        )
        await store.register_honeytoken(
            _token(token_id="BBBBBBBBBBBBBBBB", source_ip="203.0.113.8", session_id=sid),
        )
        await store.register_honeytoken(
            _token(token_id="CCCCCCCCCCCCCCCC", source_ip=None, session_id=None),
        )
        ip_7 = await store.list_honeytokens_for_source_ip("203.0.113.7")
        ip_8 = await store.list_honeytokens_for_source_ip("203.0.113.8")
    assert [t.id for t in ip_7] == ["AAAAAAAAAAAAAAAA"]
    assert [t.id for t in ip_8] == ["BBBBBBBBBBBBBBBB"]


async def test_list_honeytokens_for_source_ip_excludes_static_base(
    tmp_path: Path,
) -> None:
    """Static-base tokens have NULL source_ip; lookup by IP must not return them."""
    config = SessionStoreConfig(database_path=tmp_path / "store.db")
    async with SessionStore(config) as store:
        await store.register_honeytoken(
            _token(token_id="STATICAAAAAAAAAA", source_ip=None, session_id=None),
        )
        per_ip = await store.list_honeytokens_for_source_ip("203.0.113.7")
    assert per_ip == []


async def test_list_static_honeytokens_returns_null_source_ip_rows_only(
    tmp_path: Path,
) -> None:
    config = SessionStoreConfig(database_path=tmp_path / "store.db")
    async with SessionStore(config) as store:
        await store.register_honeytoken(
            _token(token_id="STATICAAAAAAAAAA", source_ip=None, session_id=None),
        )
        await store.register_honeytoken(
            _token(token_id="DYNAMICBBBBBBBBB", source_ip="203.0.113.7", session_id=uuid4()),
        )
        static = await store.list_static_honeytokens()
    assert [t.id for t in static] == ["STATICAAAAAAAAAA"]


async def test_list_honeytokens_orders_oldest_first(tmp_path: Path) -> None:
    config = SessionStoreConfig(database_path=tmp_path / "store.db")
    async with SessionStore(config) as store:
        # Insert two tokens for the same IP at distinct timestamps;
        # query should return oldest-first.
        await store.register_honeytoken(
            _token(
                token_id="NEWBBBBBBBBBBBBB",
                when=datetime(2026, 5, 27, tzinfo=UTC),
            ),
        )
        await store.register_honeytoken(
            _token(
                token_id="OLDAAAAAAAAAAAAA",
                when=datetime(2026, 5, 25, tzinfo=UTC),
            ),
        )
        events = await store.list_honeytokens_for_source_ip("203.0.113.7")
    assert [t.id for t in events] == ["OLDAAAAAAAAAAAAA", "NEWBBBBBBBBBBBBB"]


# ---------------------------------------------------------------------------
# Honeytokens survive session-delete (no FK cascade)
# ---------------------------------------------------------------------------


async def test_honeytoken_survives_session_delete(tmp_path: Path) -> None:
    """No FK to sessions: a callback can land months after the session is pruned."""
    config = SessionStoreConfig(database_path=tmp_path / "store.db")
    sid = uuid4()
    async with SessionStore(config) as store:
        await store.register_honeytoken(
            _token(token_id="SURVIVOAAAAAAAAA", session_id=sid),
        )
        # Direct SQL delete; the FK-free schema must not cascade.
        async with store._lock:
            store._conn.execute(  # type: ignore[union-attr]
                "DELETE FROM sessions WHERE session_id = ?",
                (str(sid),),
            )
        loaded = await store.get_honeytoken("SURVIVOAAAAAAAAA")
    assert loaded is not None


# ---------------------------------------------------------------------------
# SessionStoreReader
# ---------------------------------------------------------------------------


async def test_reader_round_trips_honeytoken(tmp_path: Path) -> None:
    config = SessionStoreConfig(database_path=tmp_path / "store.db")
    async with SessionStore(config) as writer:
        await writer.register_honeytoken(_token(token_id="READERAAAAAAAAAA"))
    async with SessionStoreReader(config) as reader:
        loaded = await reader.get_honeytoken("READERAAAAAAAAAA")
        ip_tokens = await reader.list_honeytokens_for_source_ip("203.0.113.7")
        static_tokens = await reader.list_static_honeytokens()
    assert loaded is not None
    assert loaded.id == "READERAAAAAAAAAA"
    assert [t.id for t in ip_tokens] == ["READERAAAAAAAAAA"]
    assert static_tokens == []
