"""Tests for :mod:`anglerfish.forwarder.factories`."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

from anglerfish.forwarder import event_from_session_snapshot
from anglerfish.models.session import CommandTurn, ResponseSource, SessionSnapshot


def test_event_from_session_snapshot_carries_payload() -> None:
    sid = uuid4()
    turn = CommandTurn(
        command="whoami",
        response="root",
        source=ResponseSource.AI,
        timestamp=datetime(2026, 5, 22, tzinfo=UTC),
        latency_ms=2.5,
    )
    snapshot = SessionSnapshot(
        session_id=sid,
        source_ip="203.0.113.7",
        username="root",
        fake_hostname="srv-prod-01",
        fake_username="root",
        fake_cwd="/root",
        started_at=datetime(2026, 5, 22, tzinfo=UTC),
        last_activity_at=datetime(2026, 5, 22, 0, 1, tzinfo=UTC),
        turns=(turn,),
    )
    event = event_from_session_snapshot(snapshot)
    assert event.sourcetype == "anglerfish:session"
    assert event.event["kind"] == "session"
    assert event.event["source_ip"] == "203.0.113.7"
    assert event.event["session_id"] == str(sid)
    assert event.time == snapshot.last_activity_at
