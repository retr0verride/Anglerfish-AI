"""Restart-survives-data tests for the Stage 4 DashboardState facade.

The pre-Stage-4 dashboard kept everything in memory; restarting the
process discarded every session and threat. With the facade in
place, a second DashboardState constructed against the same on-
disk store sees everything the first one wrote.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from anglerfish.config.models import SessionStoreConfig
from anglerfish.dashboard.state import DashboardState
from anglerfish.models.session import CommandTurn, ResponseSource, SessionSnapshot
from anglerfish.models.threat import ThreatAssessment
from anglerfish.sessions import SessionStore


def _snapshot(turns: tuple[CommandTurn, ...] = ()) -> SessionSnapshot:
    ts = datetime(2026, 5, 22, tzinfo=UTC)
    return SessionSnapshot(
        session_id=uuid4(),
        source_ip="203.0.113.7",
        username="root",
        fake_hostname="srv-prod-01",
        fake_username="root",
        fake_cwd="/root",
        started_at=ts,
        last_activity_at=ts,
        turns=turns,
    )


def _turn(command: str) -> CommandTurn:
    return CommandTurn(
        command=command,
        response="",
        source=ResponseSource.AI,
        timestamp=datetime(2026, 5, 22, tzinfo=UTC),
        latency_ms=1.0,
    )


async def test_sessions_survive_restart(tmp_path: Path) -> None:
    cfg = SessionStoreConfig(database_path=tmp_path / "sessions.db")
    snap = _snapshot(turns=(_turn("whoami"),))
    async with SessionStore(cfg) as store_a:
        state_a = DashboardState(store_a)
        await state_a.update_session(snap)
    async with SessionStore(cfg) as store_b:
        state_b = DashboardState(store_b)
        fetched = await state_b.get_session(snap.session_id)
    assert fetched is not None
    assert fetched.turns[0].command == "whoami"


async def test_threats_survive_restart(tmp_path: Path) -> None:
    cfg = SessionStoreConfig(database_path=tmp_path / "sessions.db")
    snap = _snapshot()
    async with SessionStore(cfg) as store_a:
        state_a = DashboardState(store_a)
        await state_a.update_session(snap)
        await state_a.record_threat(
            ThreatAssessment(
                session_id=snap.session_id,
                score=95,
                high_severity=True,
                persistence_attempted=True,
            ),
        )
    async with SessionStore(cfg) as store_b:
        state_b = DashboardState(store_b)
        threats = await state_b.get_recent_threats(limit=10)
    assert len(threats) == 1
    assert threats[0].score == 95


async def test_stats_aggregate_across_restart(tmp_path: Path) -> None:
    cfg = SessionStoreConfig(database_path=tmp_path / "sessions.db")
    snap = _snapshot(turns=(_turn("uname"), _turn("ls")))
    async with SessionStore(cfg) as store_a:
        await DashboardState(store_a).update_session(snap)
    async with SessionStore(cfg) as store_b:
        stats = await DashboardState(store_b).get_stats()
    assert stats.active_sessions == 1
    assert stats.total_commands_observed == 2


async def test_command_diff_works_after_restart(tmp_path: Path) -> None:
    """The bridge re-sends the full snapshot on every turn. After a
    restart, the diff between the persisted-turn-count and the
    incoming snapshot's turn count must still emit one COMMAND event
    per new turn (and not re-emit historical ones)."""
    cfg = SessionStoreConfig(database_path=tmp_path / "sessions.db")
    sid = uuid4()
    ts = datetime(2026, 5, 22, tzinfo=UTC)

    snap1 = SessionSnapshot(
        session_id=sid,
        source_ip="203.0.113.7",
        username="root",
        fake_hostname="srv-prod-01",
        fake_username="root",
        fake_cwd="/root",
        started_at=ts,
        last_activity_at=ts,
        turns=(_turn("a"),),
    )
    async with SessionStore(cfg) as store_a:
        await DashboardState(store_a).update_session(snap1)

    snap2 = snap1.model_copy(update={"turns": (_turn("a"), _turn("b"))})
    async with SessionStore(cfg) as store_b:
        state_b = DashboardState(store_b)
        async with state_b.subscribe() as queue:
            await state_b.update_session(snap2)
            kinds: list[str] = []
            while not queue.empty():
                kinds.append(queue.get_nowait().kind.value)
    # Two events: SESSION_UPDATED (since previous turns existed), and
    # one COMMAND for the new turn "b" only.
    assert "session_updated" in kinds
    assert kinds.count("command") == 1


async def test_end_session_persists(tmp_path: Path) -> None:
    cfg = SessionStoreConfig(database_path=tmp_path / "sessions.db")
    snap = _snapshot()
    async with SessionStore(cfg) as store_a:
        state_a = DashboardState(store_a)
        await state_a.update_session(snap)
        await state_a.end_session(snap.session_id)
    async with SessionStore(cfg) as store_b:
        state_b = DashboardState(store_b)
        active = await state_b.get_active_sessions()
    assert all(s.session_id != snap.session_id for s in active)
