"""Tests for :class:`anglerfish.dashboard.DashboardState`."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest

from anglerfish.dashboard.state import (
    DashboardEventKind,
    DashboardState,
)
from anglerfish.models.session import CommandTurn, ResponseSource, SessionSnapshot
from anglerfish.models.threat import ThreatAssessment


def _snapshot(
    *,
    session_id: UUID | None = None,
    turns: tuple[CommandTurn, ...] = (),
    last_activity_at: datetime | None = None,
) -> SessionSnapshot:
    sid = session_id if session_id is not None else uuid4()
    ts = (
        last_activity_at
        if last_activity_at is not None
        else datetime(
            2026,
            5,
            22,
            tzinfo=UTC,
        )
    )
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


async def test_publish_fans_out_to_subscribers() -> None:
    state = DashboardState()
    async with state.subscribe() as q1, state.subscribe() as q2:
        snapshot = _snapshot()
        await state.update_session(snapshot)
        events_q1 = []
        events_q2 = []
        for _ in range(1):
            events_q1.append(await q1.get())
            events_q2.append(await q2.get())
    assert events_q1[0].kind == DashboardEventKind.SESSION_STARTED
    assert events_q2[0].kind == DashboardEventKind.SESSION_STARTED


async def test_update_session_emits_session_started_then_command() -> None:
    state = DashboardState()
    snapshot = _snapshot(turns=(_turn("whoami"),))
    async with state.subscribe() as queue:
        await state.update_session(snapshot)
        events = [await queue.get() for _ in range(2)]
    kinds = [e.kind for e in events]
    assert kinds == [DashboardEventKind.SESSION_STARTED, DashboardEventKind.COMMAND]


async def test_update_session_diffs_new_turns_only() -> None:
    state = DashboardState()
    sid = uuid4()
    snap1 = _snapshot(session_id=sid, turns=(_turn("whoami"),))
    snap2 = _snapshot(session_id=sid, turns=(_turn("whoami"), _turn("id")))
    async with state.subscribe() as queue:
        await state.update_session(snap1)
        await state.update_session(snap2)
        events = [await queue.get() for _ in range(4)]
    kinds = [e.kind for e in events]
    assert kinds == [
        DashboardEventKind.SESSION_STARTED,
        DashboardEventKind.COMMAND,
        DashboardEventKind.SESSION_UPDATED,
        DashboardEventKind.COMMAND,
    ]


async def test_active_sessions_sorted_by_last_activity() -> None:
    state = DashboardState()
    old = _snapshot(
        last_activity_at=datetime(2026, 5, 22, 10, 0, tzinfo=UTC),
    )
    new = _snapshot(
        last_activity_at=datetime(2026, 5, 22, 11, 0, tzinfo=UTC),
    )
    await state.update_session(old)
    await state.update_session(new)
    sessions = await state.get_active_sessions()
    assert sessions[0].session_id == new.session_id
    assert sessions[1].session_id == old.session_id


async def test_get_session_returns_known_session() -> None:
    state = DashboardState()
    snap = _snapshot()
    await state.update_session(snap)
    assert (await state.get_session(snap.session_id)) is not None
    assert (await state.get_session(uuid4())) is None


async def test_end_session_emits_event_and_removes() -> None:
    state = DashboardState()
    snap = _snapshot()
    await state.update_session(snap)
    async with state.subscribe() as queue:
        await state.end_session(snap.session_id)
        event = await queue.get()
    assert event.kind == DashboardEventKind.SESSION_ENDED
    assert (await state.get_session(snap.session_id)) is None


async def test_end_unknown_session_is_silent() -> None:
    state = DashboardState()
    async with state.subscribe(queue_size=4) as queue:
        await state.end_session(uuid4())
        assert queue.empty()


async def test_record_threat_emits_event() -> None:
    state = DashboardState()
    sid = uuid4()
    assessment = ThreatAssessment(session_id=sid, score=42)
    async with state.subscribe() as queue:
        await state.record_threat(assessment)
        event = await queue.get()
    assert event.kind == DashboardEventKind.THREAT
    assert event.payload["session_id"] == str(sid)


async def test_get_recent_threats_ordering() -> None:
    state = DashboardState()
    for i in range(5):
        await state.record_threat(
            ThreatAssessment(session_id=uuid4(), score=i * 10),
        )
    threats = await state.get_recent_threats(limit=3)
    assert len(threats) == 3
    # Most recent first.
    assert threats[0].score == 40
    assert threats[2].score == 20


async def test_threat_replacement_for_same_session_updates_record() -> None:
    state = DashboardState()
    sid = uuid4()
    await state.record_threat(ThreatAssessment(session_id=sid, score=10))
    await state.record_threat(ThreatAssessment(session_id=sid, score=80))
    threats = await state.get_recent_threats(limit=10)
    assert len(threats) == 1
    assert threats[0].score == 80


async def test_stats() -> None:
    state = DashboardState()
    snap = _snapshot(turns=(_turn("whoami"), _turn("ls")))
    await state.update_session(snap)
    await state.record_threat(
        ThreatAssessment(session_id=snap.session_id, score=90, high_severity=True),
    )
    stats = await state.get_stats()
    assert stats.active_sessions == 1
    assert stats.total_commands_observed == 2
    assert stats.total_threat_assessments == 1
    assert stats.high_severity_count == 1
    assert stats.persistence_attempt_count == 0


async def test_session_cap_evicts_oldest() -> None:
    state = DashboardState(max_active_sessions=2)
    base = datetime(2026, 5, 22, tzinfo=UTC)
    oldest = _snapshot(last_activity_at=base)
    middle = _snapshot(last_activity_at=base + timedelta(minutes=1))
    newest = _snapshot(last_activity_at=base + timedelta(minutes=2))
    await state.update_session(oldest)
    await state.update_session(middle)
    await state.update_session(newest)
    sessions = await state.get_active_sessions()
    sids = {s.session_id for s in sessions}
    assert newest.session_id in sids
    assert middle.session_id in sids
    assert oldest.session_id not in sids


async def test_constructor_bounds() -> None:
    with pytest.raises(ValueError):
        DashboardState(max_active_sessions=0)
    with pytest.raises(ValueError):
        DashboardState(command_history_size=0)
    with pytest.raises(ValueError):
        DashboardState(threat_history_size=0)


async def test_subscribe_queue_size_validation() -> None:
    state = DashboardState()
    with pytest.raises(ValueError):
        async with state.subscribe(queue_size=0):
            pass


async def test_recent_commands_limit_validation() -> None:
    state = DashboardState()
    with pytest.raises(ValueError):
        await state.get_recent_commands(limit=0)


async def test_recent_threats_limit_validation() -> None:
    state = DashboardState()
    with pytest.raises(ValueError):
        await state.get_recent_threats(limit=0)


async def test_subscriber_count_reflects_subscriptions() -> None:
    state = DashboardState()
    assert await state.subscriber_count() == 0
    async with state.subscribe():
        assert await state.subscriber_count() == 1
    assert await state.subscriber_count() == 0


async def test_slow_subscriber_drops_oldest_event() -> None:
    state = DashboardState()
    async with state.subscribe(queue_size=2) as queue:
        # Fill queue past capacity; oldest should be dropped to make room.
        for _ in range(5):
            await state.update_session(_snapshot())
        # Drain whatever is left without blocking.
        drained = []
        while not queue.empty():
            drained.append(queue.get_nowait())
    assert len(drained) <= 2


async def test_recent_commands_returns_newest_first() -> None:
    state = DashboardState()
    snap = _snapshot(
        turns=(
            _turn("whoami", datetime(2026, 5, 22, 0, 0, tzinfo=UTC)),
            _turn("id", datetime(2026, 5, 22, 0, 1, tzinfo=UTC)),
        )
    )
    await state.update_session(snap)
    commands = await state.get_recent_commands(limit=10)
    assert commands[0]["command"] == "id"
    assert commands[1]["command"] == "whoami"
