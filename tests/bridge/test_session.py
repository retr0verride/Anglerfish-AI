"""Tests for :class:`anglerfish.bridge.SessionContext`."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from anglerfish.bridge.session import SessionContext
from anglerfish.models.session import ResponseSource


class _FakeClock:
    def __init__(self, start: datetime) -> None:
        self.now = start

    def __call__(self) -> datetime:
        return self.now

    def advance(self, delta: timedelta) -> None:
        self.now += delta


def _make_session(**overrides: object) -> SessionContext:
    base: dict[str, object] = {
        "session_id": uuid4(),
        "source_ip": "203.0.113.7",
        "username": "root",
        "fake_hostname": "srv-prod-01",
        "fake_username": "root",
        "fake_cwd": "/root",
        "history_window": 5,
    }
    base.update(overrides)
    # The constructor uses keyword-only args after session_id.
    sid = base.pop("session_id")
    return SessionContext(sid, **base)  # type: ignore[arg-type]


def test_construction_defaults() -> None:
    sid = uuid4()
    s = SessionContext(
        sid,
        source_ip="1.2.3.4",
        username="alice",
        fake_hostname="srv-prod-01",
        fake_username="root",
        fake_cwd="/root",
        history_window=3,
    )
    assert s.session_id == sid
    assert s.source_ip == "1.2.3.4"
    assert s.username == "alice"
    assert s.fake_hostname == "srv-prod-01"
    assert s.cwd == "/root"
    assert s.history() == ()


def test_negative_history_window_rejected() -> None:
    with pytest.raises(ValueError):
        _make_session(history_window=-1)


def test_non_absolute_fake_cwd_rejected() -> None:
    with pytest.raises(ValueError):
        _make_session(fake_cwd="relative")


def test_history_bounded_by_window() -> None:
    clock = _FakeClock(datetime(2026, 1, 1, tzinfo=UTC))
    s = _make_session(history_window=3, clock=clock)
    for i in range(10):
        clock.advance(timedelta(seconds=1))
        s.record(
            f"cmd-{i}",
            f"out-{i}",
            source=ResponseSource.AI,
            latency_ms=1.0,
        )
    history = s.history()
    assert len(history) == 3
    assert [t.command for t in history] == ["cmd-7", "cmd-8", "cmd-9"]


def test_zero_window_keeps_no_history() -> None:
    s = _make_session(history_window=0)
    s.record("cmd", "out", source=ResponseSource.AI, latency_ms=1.0)
    assert s.history() == ()


def test_record_updates_last_activity() -> None:
    clock = _FakeClock(datetime(2026, 1, 1, tzinfo=UTC))
    s = _make_session(clock=clock)
    initial = s.last_activity_at
    clock.advance(timedelta(seconds=10))
    s.record("cmd", "out", source=ResponseSource.AI, latency_ms=1.0)
    assert s.last_activity_at > initial


def test_update_cwd_validation() -> None:
    s = _make_session()
    s.update_cwd("/etc")
    assert s.cwd == "/etc"
    with pytest.raises(ValueError):
        s.update_cwd("relative-path")


def test_snapshot_is_frozen_view() -> None:
    s = _make_session()
    s.record("whoami", "root", source=ResponseSource.AI, latency_ms=2.5)
    snap = s.snapshot()
    assert snap.session_id == s.session_id
    assert len(snap.turns) == 1
    assert snap.turns[0].command == "whoami"
    # snapshot must not share mutable state with the session
    s.record("id", "uid=0", source=ResponseSource.AI, latency_ms=2.0)
    assert len(snap.turns) == 1
