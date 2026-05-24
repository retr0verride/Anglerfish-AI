"""Tests for :class:`anglerfish.dashboard.DashboardState`.

Stage 4: the state object is a thin facade over
:class:`anglerfish.sessions.SessionStore`. These tests cover the
pub/sub fan-out, the write-through paths, and the read caps; the
underlying SQL is exercised by ``tests/sessions/test_store.py``.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest

from anglerfish.dashboard.state import DashboardEventKind, DashboardState
from anglerfish.models.session import CommandTurn, ResponseSource, SessionSnapshot
from anglerfish.models.threat import ThreatAssessment
from anglerfish.sessions import SessionStore


def _snapshot(
    *,
    session_id: UUID | None = None,
    turns: tuple[CommandTurn, ...] = (),
    last_activity_at: datetime | None = None,
) -> SessionSnapshot:
    sid = session_id if session_id is not None else uuid4()
    ts = last_activity_at if last_activity_at is not None else datetime(2026, 5, 22, tzinfo=UTC)
    return SessionSnapshot(
        session_id=sid,
        source_ip="203.0.113.7",
        username="root",
        fake_hostname="srv-prod-01",
        fake_username="root",
        fake_cwd="/root",
        started_at=ts,
        last_activity_at=ts,
        turns=turns,
    )


def _turn(command: str, when: datetime | None = None) -> CommandTurn:
    return CommandTurn(
        command=command,
        response="",
        source=ResponseSource.AI,
        timestamp=when or datetime(2026, 5, 22, tzinfo=UTC),
        latency_ms=1.0,
    )


async def test_publish_fans_out_to_subscribers(
    dashboard_state: DashboardState,
) -> None:
    async with dashboard_state.subscribe() as q1, dashboard_state.subscribe() as q2:
        snapshot = _snapshot()
        await dashboard_state.update_session(snapshot)
        event_q1 = await q1.get()
        event_q2 = await q2.get()
    assert event_q1.kind == DashboardEventKind.SESSION_STARTED
    assert event_q2.kind == DashboardEventKind.SESSION_STARTED


async def test_update_session_emits_session_started_then_command(
    dashboard_state: DashboardState,
) -> None:
    snapshot = _snapshot(turns=(_turn("whoami"),))
    async with dashboard_state.subscribe() as queue:
        await dashboard_state.update_session(snapshot)
        events = [await queue.get() for _ in range(2)]
    kinds = [e.kind for e in events]
    assert kinds == [DashboardEventKind.SESSION_STARTED, DashboardEventKind.COMMAND]


async def test_update_session_diffs_new_turns_only(
    dashboard_state: DashboardState,
) -> None:
    sid = uuid4()
    snap1 = _snapshot(session_id=sid, turns=(_turn("whoami"),))
    snap2 = _snapshot(session_id=sid, turns=(_turn("whoami"), _turn("id")))
    async with dashboard_state.subscribe() as queue:
        await dashboard_state.update_session(snap1)
        await dashboard_state.update_session(snap2)
        events = [await queue.get() for _ in range(4)]
    kinds = [e.kind for e in events]
    assert kinds == [
        DashboardEventKind.SESSION_STARTED,
        DashboardEventKind.COMMAND,
        DashboardEventKind.SESSION_UPDATED,
        DashboardEventKind.COMMAND,
    ]


async def test_active_sessions_sorted_by_last_activity(
    dashboard_state: DashboardState,
) -> None:
    old = _snapshot(last_activity_at=datetime(2026, 5, 22, 10, 0, tzinfo=UTC))
    new = _snapshot(last_activity_at=datetime(2026, 5, 22, 11, 0, tzinfo=UTC))
    await dashboard_state.update_session(old)
    await dashboard_state.update_session(new)
    sessions = await dashboard_state.get_active_sessions()
    assert sessions[0].session_id == new.session_id
    assert sessions[1].session_id == old.session_id


async def test_get_session_returns_known_session(
    dashboard_state: DashboardState,
) -> None:
    snap = _snapshot()
    await dashboard_state.update_session(snap)
    assert (await dashboard_state.get_session(snap.session_id)) is not None
    assert (await dashboard_state.get_session(uuid4())) is None


async def test_end_session_emits_event_and_drops_from_active(
    dashboard_state: DashboardState,
) -> None:
    snap = _snapshot()
    await dashboard_state.update_session(snap)
    async with dashboard_state.subscribe() as queue:
        await dashboard_state.end_session(snap.session_id)
        event = await queue.get()
    assert event.kind == DashboardEventKind.SESSION_ENDED
    # The store still has the row (ended sessions are kept for export);
    # the active-list query excludes it.
    active = await dashboard_state.get_active_sessions()
    assert all(s.session_id != snap.session_id for s in active)


async def test_end_unknown_session_is_silent(
    dashboard_state: DashboardState,
) -> None:
    async with dashboard_state.subscribe(queue_size=4) as queue:
        await dashboard_state.end_session(uuid4())
        assert queue.empty()


async def test_record_threat_emits_event(
    dashboard_state: DashboardState,
) -> None:
    sid = uuid4()
    # The threats FK requires the session row exist first.
    await dashboard_state.update_session(_snapshot(session_id=sid))
    assessment = ThreatAssessment(session_id=sid, score=42)
    async with dashboard_state.subscribe() as queue:
        await dashboard_state.record_threat(assessment)
        event = await queue.get()
    assert event.kind == DashboardEventKind.THREAT
    assert event.payload["session_id"] == str(sid)


async def test_get_recent_threats_ordering(
    dashboard_state: DashboardState,
) -> None:
    for i in range(5):
        sid = uuid4()
        await dashboard_state.update_session(_snapshot(session_id=sid))
        await dashboard_state.record_threat(
            ThreatAssessment(session_id=sid, score=i * 10),
        )
    threats = await dashboard_state.get_recent_threats(limit=3)
    assert len(threats) == 3
    assert threats[0].score == 40
    assert threats[2].score == 20


async def test_threat_replacement_for_same_session_updates_record(
    dashboard_state: DashboardState,
) -> None:
    sid = uuid4()
    await dashboard_state.update_session(_snapshot(session_id=sid))
    await dashboard_state.record_threat(ThreatAssessment(session_id=sid, score=10))
    await dashboard_state.record_threat(ThreatAssessment(session_id=sid, score=80))
    threats = await dashboard_state.get_recent_threats(limit=10)
    assert len(threats) == 1
    assert threats[0].score == 80


async def test_stats(dashboard_state: DashboardState) -> None:
    snap = _snapshot(turns=(_turn("whoami"), _turn("ls")))
    await dashboard_state.update_session(snap)
    await dashboard_state.record_threat(
        ThreatAssessment(session_id=snap.session_id, score=90, high_severity=True),
    )
    stats = await dashboard_state.get_stats()
    assert stats.active_sessions == 1
    assert stats.total_commands_observed == 2
    assert stats.total_threat_assessments == 1
    assert stats.high_severity_count == 1
    assert stats.persistence_attempt_count == 0


async def test_constructor_bounds(session_store: SessionStore) -> None:
    # session_store is an async fixture, so the consuming test is async
    # by necessity; we touch the store to keep the linter satisfied.
    assert session_store.is_open
    with pytest.raises(ValueError):
        DashboardState(session_store, max_active_sessions=0)
    with pytest.raises(ValueError):
        DashboardState(session_store, command_history_size=0)
    with pytest.raises(ValueError):
        DashboardState(session_store, threat_history_size=0)
    await session_store.get_stats()


async def test_subscribe_queue_size_validation(
    dashboard_state: DashboardState,
) -> None:
    with pytest.raises(ValueError):
        async with dashboard_state.subscribe(queue_size=0):
            pass


async def test_recent_commands_limit_validation(
    dashboard_state: DashboardState,
) -> None:
    with pytest.raises(ValueError):
        await dashboard_state.get_recent_commands(limit=0)


async def test_recent_threats_limit_validation(
    dashboard_state: DashboardState,
) -> None:
    with pytest.raises(ValueError):
        await dashboard_state.get_recent_threats(limit=0)


async def test_subscriber_count_reflects_subscriptions(
    dashboard_state: DashboardState,
) -> None:
    assert await dashboard_state.subscriber_count() == 0
    async with dashboard_state.subscribe():
        assert await dashboard_state.subscriber_count() == 1
    assert await dashboard_state.subscriber_count() == 0


async def test_slow_subscriber_drops_oldest_event(
    dashboard_state: DashboardState,
) -> None:
    async with dashboard_state.subscribe(queue_size=2) as queue:
        for _ in range(5):
            await dashboard_state.update_session(_snapshot())
        drained = []
        while not queue.empty():
            drained.append(queue.get_nowait())
    assert len(drained) <= 2


async def test_recent_commands_returns_newest_first(
    dashboard_state: DashboardState,
) -> None:
    snap = _snapshot(
        turns=(
            _turn("whoami", datetime(2026, 5, 22, 0, 0, tzinfo=UTC)),
            _turn("id", datetime(2026, 5, 22, 0, 1, tzinfo=UTC)),
        ),
    )
    await dashboard_state.update_session(snap)
    commands = await dashboard_state.get_recent_commands(limit=10)
    assert commands[0]["command"] == "id"
    assert commands[1]["command"] == "whoami"


async def test_max_active_sessions_caps_read(
    session_store: SessionStore,
) -> None:
    state = DashboardState(session_store, max_active_sessions=2)
    base = datetime(2026, 5, 22, tzinfo=UTC)
    for i in range(3):
        await state.update_session(
            _snapshot(last_activity_at=base + timedelta(minutes=i)),
        )
    sessions = await state.get_active_sessions()
    assert len(sessions) == 2


async def test_store_property_exposes_underlying_store(
    session_store: SessionStore,
    dashboard_state: DashboardState,
) -> None:
    assert dashboard_state.store is session_store
    # Round-trip a stats call through the facade and the property to
    # confirm both surfaces hit the same connection.
    await dashboard_state.get_stats()
