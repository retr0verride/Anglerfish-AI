"""Helpers that turn typed runtime objects into :class:`ForwarderEvent`\\ s.

These live alongside the forwarder rather than inside each producing
subsystem so that the forwarder remains the single source of truth
about the wire format for HEC and JSONL records.
"""

from __future__ import annotations

from anglerfish.forwarder.event import ForwarderEvent
from anglerfish.models.session import SessionSnapshot

__all__ = ["event_from_session_snapshot"]


def event_from_session_snapshot(snapshot: SessionSnapshot) -> ForwarderEvent:
    """Wrap a :class:`SessionSnapshot` in a forwardable event."""
    payload = snapshot.model_dump(mode="json")
    payload["kind"] = "session"
    return ForwarderEvent(
        event=payload,
        sourcetype="anglerfish:session",
        time=snapshot.last_activity_at,
    )
