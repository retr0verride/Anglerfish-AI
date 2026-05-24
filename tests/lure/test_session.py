"""Tests for :class:`anglerfish.lure.session.LureSessionContext`."""

from __future__ import annotations

from uuid import uuid4

import pytest

from anglerfish.lure.session import LureSessionContext


def _make() -> LureSessionContext:
    return LureSessionContext(
        uuid4(),
        source_ip="203.0.113.7",
        username="alice",
        hostname="srv-prod-01",
        cwd="/home/alice",
    )


def test_session_defaults_round_trip() -> None:
    s = _make()
    assert s.source_ip == "203.0.113.7"
    assert s.username == "alice"
    assert s.hostname == "srv-prod-01"
    assert s.cwd == "/home/alice"
    assert s.command_count() == 0


def test_cwd_is_normalised_on_construction() -> None:
    s = LureSessionContext(
        uuid4(),
        source_ip="1.1.1.1",
        username="bob",
        hostname="h",
        cwd="/home/bob/./../bob",
    )
    assert s.cwd == "/home/bob"


def test_update_cwd_normalises_input() -> None:
    s = _make()
    s.update_cwd("/var/log/../tmp")
    assert s.cwd == "/var/tmp"


def test_record_appends_to_history_in_order() -> None:
    s = _make()
    s.record("ls", response_source="native")
    s.record("whoami", response_source="native")
    s.record("cat /etc/passwd", response_source="native")
    history = list(s.history())
    assert [r.command for r in history] == ["ls", "whoami", "cat /etc/passwd"]
    assert s.command_count() == 3


def test_history_is_capped_by_window() -> None:
    s = LureSessionContext(
        uuid4(),
        source_ip="1.1.1.1",
        username="u",
        hostname="h",
        cwd="/",
        history_window=3,
    )
    for i in range(10):
        s.record(f"cmd-{i}", response_source="native")
    commands = [r.command for r in s.history()]
    assert commands == ["cmd-7", "cmd-8", "cmd-9"]


def test_history_window_must_be_positive() -> None:
    with pytest.raises(ValueError, match="history_window"):
        LureSessionContext(
            uuid4(),
            source_ip="1.1.1.1",
            username="u",
            hostname="h",
            cwd="/",
            history_window=0,
        )


def test_opened_at_is_timezone_aware() -> None:
    s = _make()
    assert s.opened_at.tzinfo is not None


def test_record_stores_response_source() -> None:
    s = _make()
    s.record("ls", response_source="bridge")
    record = next(iter(s.history()))
    assert record.response_source == "bridge"
