"""Tests for the Stage 10 slice 2 fake_persistence_state table + SessionStore CRUD."""

from __future__ import annotations

import asyncio
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from anglerfish.config.models import SessionStoreConfig
from anglerfish.models.persistence import PersistenceEvent
from anglerfish.sessions import SessionStore
from anglerfish.sessions.schema import CURRENT_SCHEMA_VERSION, run_migrations


def _event(
    kind: str = "crontab",
    *,
    sub_key: str | None = None,
    payload: str = "0 * * * * /tmp/.x",
    source: str = "regex",
) -> PersistenceEvent:
    return PersistenceEvent(
        kind=kind,  # type: ignore[arg-type]
        sub_key=sub_key,
        payload=payload,
        source=source,  # type: ignore[arg-type]
    )


# ---------------------------------------------------------------------------
# Schema v5 migration
# ---------------------------------------------------------------------------


def test_current_schema_version_at_or_above_five() -> None:
    # Engaged persistence table arrived at v5; assertion tracks the
    # floor so future stages do not churn this test.
    assert CURRENT_SCHEMA_VERSION >= 5


def test_migration_creates_fake_persistence_state_table(tmp_path: Path) -> None:
    db = tmp_path / "schema.db"
    conn = sqlite3.connect(db)
    try:
        run_migrations(conn)
        rows = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='fake_persistence_state'",
        ).fetchall()
        assert rows == [("fake_persistence_state",)]
    finally:
        conn.close()


def test_migration_enforces_uniqueness_constraint(tmp_path: Path) -> None:
    db = tmp_path / "schema.db"
    conn = sqlite3.connect(db)
    try:
        run_migrations(conn)
        sid = str(uuid4())
        ts = "2026-05-26T12:00:00+00:00"
        conn.execute(
            "INSERT INTO fake_persistence_state "
            "(source_ip, kind, sub_key, payload, source, created_at, session_id) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            ("203.0.113.7", "crontab", None, "0 * * * *", "regex", ts, sid),
        )
        # Same (source_ip, kind, sub_key, created_at) replay: INSERT OR
        # IGNORE returns rowcount=0; plain INSERT raises IntegrityError.
        cur = conn.execute(
            "INSERT OR IGNORE INTO fake_persistence_state "
            "(source_ip, kind, sub_key, payload, source, created_at, session_id) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            ("203.0.113.7", "crontab", None, "different payload", "regex", ts, sid),
        )
        assert cur.rowcount == 0
        count = conn.execute(
            "SELECT COUNT(*) FROM fake_persistence_state WHERE source_ip = ?",
            ("203.0.113.7",),
        ).fetchone()[0]
        assert count == 1
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# SessionStore.record_persistence_event
# ---------------------------------------------------------------------------


async def test_record_persistence_event_round_trip(tmp_path: Path) -> None:
    config = SessionStoreConfig(database_path=tmp_path / "store.db")
    async with SessionStore(config) as store:
        inserted = await store.record_persistence_event(
            _event(payload="0 * * * * /tmp/.x"),
            source_ip="203.0.113.7",
            session_id=uuid4(),
            created_at=datetime(2026, 5, 26, 12, 0, tzinfo=UTC),
        )
        assert inserted is True
        events = await store.list_persistence_events_for_source_ip("203.0.113.7")
    assert len(events) == 1
    assert events[0].kind == "crontab"
    assert events[0].payload == "0 * * * * /tmp/.x"
    assert events[0].source == "regex"


async def test_record_persistence_event_replay_returns_false(tmp_path: Path) -> None:
    """Re-inserting the same audit line is idempotent."""
    config = SessionStoreConfig(database_path=tmp_path / "store.db")
    sid = uuid4()
    when = datetime(2026, 5, 26, 12, 0, tzinfo=UTC)
    async with SessionStore(config) as store:
        first = await store.record_persistence_event(
            _event(),
            source_ip="203.0.113.7",
            session_id=sid,
            created_at=when,
        )
        replay = await store.record_persistence_event(
            _event(payload="different but same key"),
            source_ip="203.0.113.7",
            session_id=sid,
            created_at=when,
        )
        events = await store.list_persistence_events_for_source_ip("203.0.113.7")
    assert first is True
    assert replay is False
    assert len(events) == 1


async def test_record_persistence_event_distinct_timestamps_append(
    tmp_path: Path,
) -> None:
    """Same kind + sub_key at different created_at -> separate rows."""
    config = SessionStoreConfig(database_path=tmp_path / "store.db")
    sid = uuid4()
    async with SessionStore(config) as store:
        await store.record_persistence_event(
            _event(payload="first"),
            source_ip="203.0.113.7",
            session_id=sid,
            created_at=datetime(2026, 5, 26, 12, 0, tzinfo=UTC),
        )
        await store.record_persistence_event(
            _event(payload="second"),
            source_ip="203.0.113.7",
            session_id=sid,
            created_at=datetime(2026, 5, 26, 13, 0, tzinfo=UTC),
        )
        events = await store.list_persistence_events_for_source_ip("203.0.113.7")
    assert [e.payload for e in events] == ["first", "second"]


async def test_list_persistence_events_oldest_first(tmp_path: Path) -> None:
    """list_persistence_events orders by created_at ASC."""
    config = SessionStoreConfig(database_path=tmp_path / "store.db")
    sid = uuid4()
    async with SessionStore(config) as store:
        # Insert newest-first; query should return oldest-first.
        await store.record_persistence_event(
            _event(kind="authorized_keys", payload="key2"),
            source_ip="203.0.113.7",
            session_id=sid,
            created_at=datetime(2026, 5, 27, 12, 0, tzinfo=UTC),
        )
        await asyncio.sleep(0.01)
        await store.record_persistence_event(
            _event(kind="authorized_keys", payload="key1"),
            source_ip="203.0.113.7",
            session_id=sid,
            created_at=datetime(2026, 5, 26, 12, 0, tzinfo=UTC),
        )
        events = await store.list_persistence_events_for_source_ip("203.0.113.7")
    assert [e.payload for e in events] == ["key1", "key2"]


async def test_list_persistence_events_filters_by_source_ip(
    tmp_path: Path,
) -> None:
    config = SessionStoreConfig(database_path=tmp_path / "store.db")
    sid = uuid4()
    async with SessionStore(config) as store:
        await store.record_persistence_event(
            _event(payload="for-ip-7"),
            source_ip="203.0.113.7",
            session_id=sid,
            created_at=datetime(2026, 5, 26, 12, 0, tzinfo=UTC),
        )
        await store.record_persistence_event(
            _event(payload="for-ip-8"),
            source_ip="203.0.113.8",
            session_id=sid,
            created_at=datetime(2026, 5, 26, 12, 0, tzinfo=UTC),
        )
        ip_7 = await store.list_persistence_events_for_source_ip("203.0.113.7")
        ip_8 = await store.list_persistence_events_for_source_ip("203.0.113.8")
    assert [e.payload for e in ip_7] == ["for-ip-7"]
    assert [e.payload for e in ip_8] == ["for-ip-8"]


async def test_persistence_state_survives_session_delete(tmp_path: Path) -> None:
    """No FK to sessions: deleting a session does NOT cascade."""
    config = SessionStoreConfig(database_path=tmp_path / "store.db")
    sid = uuid4()
    async with SessionStore(config) as store:
        await store.record_persistence_event(
            _event(),
            source_ip="203.0.113.7",
            session_id=sid,
            created_at=datetime(2026, 5, 26, 12, 0, tzinfo=UTC),
        )
        # Direct SQL delete (no session row exists; we never inserted
        # one. The test confirms no FK rejects the persistence insert
        # AND no FK cascades a delete.)
        async with store._lock:  # type: ignore[attr-defined]
            store._conn.execute(  # type: ignore[union-attr]
                "DELETE FROM sessions WHERE session_id = ?",
                (str(sid),),
            )
        events = await store.list_persistence_events_for_source_ip("203.0.113.7")
    assert len(events) == 1


async def test_list_persistence_events_for_unknown_ip_returns_empty(
    tmp_path: Path,
) -> None:
    config = SessionStoreConfig(database_path=tmp_path / "store.db")
    async with SessionStore(config) as store:
        events = await store.list_persistence_events_for_source_ip("203.0.113.255")
    assert events == []


async def test_record_persistence_event_preserves_llm_source(tmp_path: Path) -> None:
    """LLM-classified rows round-trip with source='llm'."""
    config = SessionStoreConfig(database_path=tmp_path / "store.db")
    async with SessionStore(config) as store:
        await store.record_persistence_event(
            _event(source="llm"),
            source_ip="203.0.113.7",
            session_id=uuid4(),
            created_at=datetime(2026, 5, 26, 12, 0, tzinfo=UTC),
        )
        events = await store.list_persistence_events_for_source_ip("203.0.113.7")
    assert events[0].source == "llm"
