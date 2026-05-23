"""Tests for the shared data models in :mod:`anglerfish.models.session`."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

import pytest
from pydantic import ValidationError

from anglerfish.models.session import (
    BridgeResponse,
    CommandTurn,
    ResponseSource,
    SessionSnapshot,
)


def test_response_source_values() -> None:
    assert ResponseSource.AI.value == "ai"
    assert ResponseSource.FALLBACK.value == "fallback"
    assert ResponseSource.REJECTED.value == "rejected"


def test_command_turn_constructs() -> None:
    turn = CommandTurn(
        command="ls",
        response="a b c",
        source=ResponseSource.AI,
        timestamp=datetime(2026, 1, 1, tzinfo=UTC),
        latency_ms=12.5,
    )
    assert turn.command == "ls"
    assert turn.latency_ms == 12.5


def test_command_turn_is_frozen() -> None:
    turn = CommandTurn(
        command="ls",
        response="x",
        source=ResponseSource.AI,
        timestamp=datetime(2026, 1, 1, tzinfo=UTC),
        latency_ms=1.0,
    )
    with pytest.raises(ValidationError):
        turn.command = "id"  # type: ignore[misc]


def test_command_turn_rejects_negative_latency() -> None:
    with pytest.raises(ValidationError):
        CommandTurn(
            command="ls",
            response="x",
            source=ResponseSource.AI,
            timestamp=datetime(2026, 1, 1, tzinfo=UTC),
            latency_ms=-1.0,
        )


def test_bridge_response_constructs() -> None:
    r = BridgeResponse(text="ok", source=ResponseSource.AI, latency_ms=2.0)
    assert r.text == "ok"


def test_session_snapshot_constructs() -> None:
    turn = CommandTurn(
        command="whoami",
        response="root",
        source=ResponseSource.AI,
        timestamp=datetime(2026, 1, 1, tzinfo=UTC),
        latency_ms=3.0,
    )
    snap = SessionSnapshot(
        session_id=uuid4(),
        source_ip="1.2.3.4",
        username="root",
        fake_hostname="srv-prod-01",
        fake_username="root",
        fake_cwd="/root",
        started_at=datetime(2026, 1, 1, tzinfo=UTC),
        last_activity_at=datetime(2026, 1, 1, 0, 0, 5, tzinfo=UTC),
        turns=(turn,),
    )
    assert len(snap.turns) == 1
    assert snap.turns[0].command == "whoami"
