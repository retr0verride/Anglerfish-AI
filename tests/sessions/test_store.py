"""Tests for :class:`anglerfish.sessions.SessionStore`.

The store is exercised through its public async API; SQL-level
behaviour is observed via the public reads. No tests reach into
:attr:`SessionStore._conn` directly so the schema is free to evolve
without churning these.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID, uuid4

import pytest

from anglerfish.config.models import SessionStoreConfig
from anglerfish.models.session import CommandTurn, ResponseSource, SessionSnapshot
from anglerfish.models.threat import ThreatAssessment, ThreatTechnique
from anglerfish.sessions import SessionStore
from anglerfish.sessions.schema import (
    CURRENT_SCHEMA_VERSION,
    current_schema_version,
    run_migrations,
)


def _snapshot(
    *,
    session_id: UUID | None = None,
    turns: tuple[CommandTurn, ...] = (),
    started_at: datetime | None = None,
    last_activity_at: datetime | None = None,
) -> SessionSnapshot:
    sid = session_id if session_id is not None else uuid4()
    ts = started_at or datetime(2026, 5, 22, tzinfo=UTC)
    return SessionSnapshot(
        session_id=sid,
        source_ip="203.0.113.7",
        username="root",
        fake_hostname="srv-prod-01",
        fake_username="root",
        fake_cwd="/root",
        started_at=ts,
        last_activity_at=last_activity_at or ts,
        turns=turns,
    )


def _turn(command: str, when: datetime | None = None) -> CommandTurn:
    return CommandTurn(
        command=command,
        response="OK",
        source=ResponseSource.AI,
        timestamp=when or datetime(2026, 5, 22, tzinfo=UTC),
        latency_ms=1.5,
    )


# ---------------------------------------------------------------------------
# Lifecycle
# ---------------------------------------------------------------------------


async def test_open_creates_database_file(tmp_path: Path) -> None:
    db = tmp_path / "sessions.db"
    store = SessionStore(SessionStoreConfig(database_path=db))
    await store.open()
    try:
        assert db.exists()
        assert store.is_open
    finally:
        await store.aclose()


async def test_open_is_idempotent(session_store: SessionStore) -> None:
    # The fixture already opened it once; calling open again is a no-op.
    await session_store.open()
    assert session_store.is_open


async def test_aclose_is_idempotent(tmp_path: Path) -> None:
    store = SessionStore(SessionStoreConfig(database_path=tmp_path / "sessions.db"))
    await store.open()
    await store.aclose()
    await store.aclose()  # second call should not raise
    assert not store.is_open


async def test_async_context_manager_opens_and_closes(tmp_path: Path) -> None:
    cfg = SessionStoreConfig(database_path=tmp_path / "sessions.db")
    async with SessionStore(cfg) as store:
        assert store.is_open
    assert not store.is_open


async def test_use_before_open_raises(tmp_path: Path) -> None:
    store = SessionStore(SessionStoreConfig(database_path=tmp_path / "sessions.db"))
    with pytest.raises(RuntimeError, match="open"):
        await store.get_stats()


# ---------------------------------------------------------------------------
# Schema migrations
# ---------------------------------------------------------------------------


async def test_schema_version_set_on_open(session_store: SessionStore) -> None:
    # Round-trip a stats call so we go through the async lock at least
    # once, then read the private connection to assert the meta row.
    await session_store.get_stats()
    conn = session_store._conn
    assert conn is not None
    assert current_schema_version(conn) == CURRENT_SCHEMA_VERSION


async def test_run_migrations_is_idempotent(session_store: SessionStore) -> None:
    await session_store.get_stats()
    conn = session_store._conn
    assert conn is not None
    run_migrations(conn)
    run_migrations(conn)
    assert current_schema_version(conn) == CURRENT_SCHEMA_VERSION


# ---------------------------------------------------------------------------
# Writes
# ---------------------------------------------------------------------------


async def test_upsert_session_round_trip(session_store: SessionStore) -> None:
    snap = _snapshot()
    await session_store.upsert_session(snap)
    fetched = await session_store.get_session(snap.session_id)
    assert fetched is not None
    assert fetched.source_ip == snap.source_ip
    assert fetched.turns == ()


async def test_upsert_updates_existing_row(session_store: SessionStore) -> None:
    sid = uuid4()
    base = datetime(2026, 5, 22, tzinfo=UTC)
    await session_store.upsert_session(_snapshot(session_id=sid, last_activity_at=base))
    later = base + timedelta(minutes=5)
    await session_store.upsert_session(_snapshot(session_id=sid, last_activity_at=later))
    fetched = await session_store.get_session(sid)
    assert fetched is not None
    assert fetched.last_activity_at == later


async def test_record_turn_assigns_sequential_numbers(
    session_store: SessionStore,
) -> None:
    snap = _snapshot()
    await session_store.upsert_session(snap)
    for cmd in ("whoami", "id", "ls /"):
        await session_store.record_turn(snap.session_id, _turn(cmd))
    fetched = await session_store.get_session(snap.session_id)
    assert fetched is not None
    assert [t.command for t in fetched.turns] == ["whoami", "id", "ls /"]


async def test_record_turn_updates_command_count(
    session_store: SessionStore,
) -> None:
    snap = _snapshot()
    await session_store.upsert_session(snap)
    await session_store.record_turn(snap.session_id, _turn("whoami"))
    await session_store.record_turn(snap.session_id, _turn("id"))
    stats = await session_store.get_stats()
    assert stats.total_commands_observed == 2


async def test_upsert_after_record_turn_does_not_reset_count(
    session_store: SessionStore,
) -> None:
    """The ON CONFLICT path must NOT overwrite command_count, since
    record_turn maintains it; otherwise live updates double-count."""
    snap = _snapshot()
    await session_store.upsert_session(snap)
    await session_store.record_turn(snap.session_id, _turn("whoami"))
    # Re-upsert with the original (empty) turns tuple; would zero the
    # count out if the ON CONFLICT clause included command_count.
    await session_store.upsert_session(snap)
    stats = await session_store.get_stats()
    assert stats.total_commands_observed == 1


async def test_end_session_excludes_from_active_list(
    session_store: SessionStore,
) -> None:
    snap = _snapshot()
    await session_store.upsert_session(snap)
    await session_store.end_session(snap.session_id, datetime.now(tz=UTC))
    active = await session_store.get_active_sessions()
    assert all(s.session_id != snap.session_id for s in active)


async def test_record_threat_round_trip(session_store: SessionStore) -> None:
    snap = _snapshot()
    await session_store.upsert_session(snap)
    assessment = ThreatAssessment(
        session_id=snap.session_id,
        score=75,
        high_severity=True,
        techniques=(ThreatTechnique(id="T1059", name="Command Execution", matches=("bash",)),),
        notes=("LLM flagged shell pipeline",),
    )
    await session_store.record_threat(assessment)
    threats = await session_store.get_recent_threats(limit=10)
    assert len(threats) == 1
    assert threats[0].score == 75
    assert threats[0].techniques[0].id == "T1059"
    assert threats[0].notes == ("LLM flagged shell pipeline",)


async def test_record_threat_replaces_for_same_session(
    session_store: SessionStore,
) -> None:
    snap = _snapshot()
    await session_store.upsert_session(snap)
    await session_store.record_threat(
        ThreatAssessment(session_id=snap.session_id, score=10),
    )
    await session_store.record_threat(
        ThreatAssessment(session_id=snap.session_id, score=85, high_severity=True),
    )
    threats = await session_store.get_recent_threats(limit=10)
    assert len(threats) == 1
    assert threats[0].score == 85


# ---------------------------------------------------------------------------
# Reads
# ---------------------------------------------------------------------------


async def test_get_session_returns_none_for_unknown(
    session_store: SessionStore,
) -> None:
    assert await session_store.get_session(uuid4()) is None


async def test_get_active_sessions_sorted_by_last_activity(
    session_store: SessionStore,
) -> None:
    base = datetime(2026, 5, 22, tzinfo=UTC)
    old = _snapshot(last_activity_at=base)
    new = _snapshot(last_activity_at=base + timedelta(minutes=10))
    await session_store.upsert_session(old)
    await session_store.upsert_session(new)
    sessions = await session_store.get_active_sessions()
    assert sessions[0].session_id == new.session_id
    assert sessions[1].session_id == old.session_id


async def test_get_active_sessions_respects_limit(
    session_store: SessionStore,
) -> None:
    base = datetime(2026, 5, 22, tzinfo=UTC)
    for i in range(5):
        await session_store.upsert_session(
            _snapshot(last_activity_at=base + timedelta(minutes=i)),
        )
    sessions = await session_store.get_active_sessions(limit=2)
    assert len(sessions) == 2


async def test_get_active_sessions_rejects_nonpositive_limit(
    session_store: SessionStore,
) -> None:
    with pytest.raises(ValueError):
        await session_store.get_active_sessions(limit=0)


async def test_get_sessions_in_range_filters_by_started_at(
    session_store: SessionStore,
) -> None:
    base = datetime(2026, 5, 22, tzinfo=UTC)
    in_range = _snapshot(started_at=base)
    out_of_range = _snapshot(started_at=base - timedelta(days=10))
    await session_store.upsert_session(in_range)
    await session_store.upsert_session(out_of_range)
    found = await session_store.get_sessions_in_range(
        start=base - timedelta(hours=1),
        end=base + timedelta(hours=1),
    )
    ids = {s.session_id for s in found}
    assert in_range.session_id in ids
    assert out_of_range.session_id not in ids


async def test_get_sessions_in_range_validates_bounds(
    session_store: SessionStore,
) -> None:
    now = datetime.now(tz=UTC)
    with pytest.raises(ValueError):
        await session_store.get_sessions_in_range(
            start=now,
            end=now - timedelta(hours=1),
        )
    with pytest.raises(ValueError):
        await session_store.get_sessions_in_range(
            start=now,
            end=now,
            limit=0,
        )
    with pytest.raises(ValueError):
        await session_store.get_sessions_in_range(
            start=now,
            end=now,
            limit=10_001,
        )


async def test_get_recent_commands_newest_first(
    session_store: SessionStore,
) -> None:
    snap = _snapshot()
    await session_store.upsert_session(snap)
    await session_store.record_turn(
        snap.session_id,
        _turn("whoami", datetime(2026, 5, 22, 0, 0, tzinfo=UTC)),
    )
    await session_store.record_turn(
        snap.session_id,
        _turn("id", datetime(2026, 5, 22, 0, 1, tzinfo=UTC)),
    )
    commands = await session_store.get_recent_commands(limit=10)
    assert [t.command for _, t in commands] == ["id", "whoami"]


async def test_get_recent_commands_rejects_nonpositive_limit(
    session_store: SessionStore,
) -> None:
    with pytest.raises(ValueError):
        await session_store.get_recent_commands(limit=0)


async def test_get_recent_threats_rejects_nonpositive_limit(
    session_store: SessionStore,
) -> None:
    with pytest.raises(ValueError):
        await session_store.get_recent_threats(limit=0)


async def test_get_stats_counts(session_store: SessionStore) -> None:
    base = datetime(2026, 5, 22, tzinfo=UTC)
    snap1 = _snapshot(last_activity_at=base)
    snap2 = _snapshot(last_activity_at=base + timedelta(minutes=1))
    await session_store.upsert_session(snap1)
    await session_store.upsert_session(snap2)
    await session_store.record_turn(snap1.session_id, _turn("a"))
    await session_store.record_turn(snap2.session_id, _turn("b"))
    await session_store.record_threat(
        ThreatAssessment(
            session_id=snap1.session_id,
            score=90,
            high_severity=True,
            persistence_attempted=True,
        ),
    )
    await session_store.end_session(snap2.session_id, base + timedelta(minutes=2))
    stats = await session_store.get_stats()
    assert stats.active_sessions == 1
    assert stats.total_commands_observed == 2
    assert stats.total_threat_assessments == 1
    assert stats.high_severity_count == 1
    assert stats.persistence_attempt_count == 1


# ---------------------------------------------------------------------------
# Concurrency
# ---------------------------------------------------------------------------


async def test_concurrent_turn_writes_get_unique_sequences(
    session_store: SessionStore,
) -> None:
    snap = _snapshot()
    await session_store.upsert_session(snap)
    await asyncio.gather(
        *[session_store.record_turn(snap.session_id, _turn(f"cmd{i}")) for i in range(20)],
    )
    fetched = await session_store.get_session(snap.session_id)
    assert fetched is not None
    assert len(fetched.turns) == 20
    assert len({t.command for t in fetched.turns}) == 20
