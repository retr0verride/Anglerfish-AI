"""Tests for the Stage 7 intents table and SessionStore methods."""

from __future__ import annotations

import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import pytest

from anglerfish.config.models import SessionStoreConfig
from anglerfish.models import (
    CommandTurn,
    IntentSummary,
    ResponseSource,
    SessionSnapshot,
)
from anglerfish.sessions import SessionStore
from anglerfish.sessions.schema import (
    CURRENT_SCHEMA_VERSION,
    current_schema_version,
    run_migrations,
)


def _snapshot() -> SessionSnapshot:
    now = datetime(2026, 5, 25, 12, 0, tzinfo=UTC)
    return SessionSnapshot(
        session_id=uuid4(),
        source_ip="203.0.113.7",
        username="root",
        fake_hostname="srv-prod-01",
        fake_username="root",
        fake_cwd="/root",
        started_at=now,
        last_activity_at=now,
        turns=(
            CommandTurn(
                command="ls",
                response="",
                source=ResponseSource.AI,
                timestamp=now,
                latency_ms=1.0,
            ),
        ),
    )


def _intent_for(session_id) -> IntentSummary:
    return IntentSummary(
        session_id=session_id,
        actor_profile="automated",
        intent="Deploy cryptominer.",
        why="Downloaded miner; configured pool URL.",
        matched_techniques=("T1059.004", "T1496"),
        confidence="high",
        summary="Automated IoT-botnet-style cryptomining session.",
        extracted_at=datetime(2026, 5, 25, 12, 30, tzinfo=UTC),
    )


# ---------------------------------------------------------------------------
# Schema migration
# ---------------------------------------------------------------------------


def test_current_schema_version_is_at_least_two() -> None:
    """Stage 7 introduced v2; later stages bump it further. v2 is the floor."""
    assert CURRENT_SCHEMA_VERSION >= 2


def test_migration_creates_intents_table(tmp_path: Path) -> None:
    db = tmp_path / "schema.db"
    conn = sqlite3.connect(db)
    try:
        version = run_migrations(conn)
        assert version >= 2
        rows = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='intents'"
        ).fetchall()
        assert rows == [("intents",)]
    finally:
        conn.close()


def test_migration_is_idempotent(tmp_path: Path) -> None:
    db = tmp_path / "schema.db"
    conn = sqlite3.connect(db)
    try:
        run_migrations(conn)
        # Re-running on an up-to-date DB is a no-op.
        run_migrations(conn)
        assert current_schema_version(conn) == CURRENT_SCHEMA_VERSION
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# upsert_intent / get_intent round-trip
# ---------------------------------------------------------------------------


async def test_upsert_and_get_intent_round_trip(tmp_path: Path) -> None:
    snapshot = _snapshot()
    intent = _intent_for(snapshot.session_id)
    config = SessionStoreConfig(database_path=tmp_path / "store.db")
    async with SessionStore(config) as store:
        await store.upsert_session(snapshot)
        await store.upsert_intent(intent)
        loaded = await store.get_intent(snapshot.session_id)

    assert loaded is not None
    assert loaded.session_id == intent.session_id
    assert loaded.actor_profile == "automated"
    assert loaded.matched_techniques == ("T1059.004", "T1496")
    assert loaded.confidence == "high"
    assert loaded.summary.startswith("Automated")
    assert loaded.extracted_at == intent.extracted_at


async def test_upsert_intent_overwrites_existing_row(tmp_path: Path) -> None:
    snapshot = _snapshot()
    config = SessionStoreConfig(database_path=tmp_path / "store.db")
    first = _intent_for(snapshot.session_id)
    second = IntentSummary(
        session_id=snapshot.session_id,
        actor_profile="targeted",
        intent="Lateral movement.",
        why="Enumerated internal hostnames.",
        matched_techniques=("T1083",),
        confidence="medium",
        summary="Targeted recon session.",
        extracted_at=datetime(2026, 5, 25, 13, 0, tzinfo=UTC),
    )
    async with SessionStore(config) as store:
        await store.upsert_session(snapshot)
        await store.upsert_intent(first)
        await store.upsert_intent(second)
        loaded = await store.get_intent(snapshot.session_id)
    assert loaded is not None
    assert loaded.actor_profile == "targeted"
    assert loaded.confidence == "medium"
    assert loaded.matched_techniques == ("T1083",)


async def test_get_intent_returns_none_for_unknown_session(tmp_path: Path) -> None:
    config = SessionStoreConfig(database_path=tmp_path / "store.db")
    async with SessionStore(config) as store:
        loaded = await store.get_intent(uuid4())
    assert loaded is None


async def test_get_intent_returns_none_before_upsert(tmp_path: Path) -> None:
    snapshot = _snapshot()
    config = SessionStoreConfig(database_path=tmp_path / "store.db")
    async with SessionStore(config) as store:
        await store.upsert_session(snapshot)
        loaded = await store.get_intent(snapshot.session_id)
    assert loaded is None


async def test_upsert_intent_without_session_fk_raises(tmp_path: Path) -> None:
    """Cascade FK rejects intents for unknown session_ids."""
    config = SessionStoreConfig(database_path=tmp_path / "store.db")
    async with SessionStore(config) as store:
        intent = _intent_for(uuid4())  # never persisted
        with pytest.raises(sqlite3.IntegrityError):
            await store.upsert_intent(intent)


async def test_session_delete_cascades_intent(tmp_path: Path) -> None:
    """Deleting the session row drops the intent via ON DELETE CASCADE."""
    snapshot = _snapshot()
    intent = _intent_for(snapshot.session_id)
    config = SessionStoreConfig(database_path=tmp_path / "store.db")
    async with SessionStore(config) as store:
        await store.upsert_session(snapshot)
        await store.upsert_intent(intent)
        # Confirm present.
        assert await store.get_intent(snapshot.session_id) is not None
        # Delete the session directly via the connection (the public
        # store has no delete method; cascade is a schema invariant
        # that should hold regardless of caller).
        async with store._lock:
            store._conn.execute(  # type: ignore[union-attr]
                "DELETE FROM sessions WHERE session_id = ?",
                (str(snapshot.session_id),),
            )
        assert await store.get_intent(snapshot.session_id) is None


async def test_empty_matched_techniques_round_trip(tmp_path: Path) -> None:
    """The placeholder path emits matched_techniques=(); JSON survives."""
    snapshot = _snapshot()
    intent = IntentSummary(
        session_id=snapshot.session_id,
        actor_profile="opportunistic",
        intent="Session below threshold.",
        why="Insufficient behaviour.",
        matched_techniques=(),
        confidence="low",
        summary="Placeholder.",
        extracted_at=datetime(2026, 5, 25, 12, 0, tzinfo=UTC),
    )
    config = SessionStoreConfig(database_path=tmp_path / "store.db")
    async with SessionStore(config) as store:
        await store.upsert_session(snapshot)
        await store.upsert_intent(intent)
        loaded = await store.get_intent(snapshot.session_id)
    assert loaded is not None
    assert loaded.matched_techniques == ()
