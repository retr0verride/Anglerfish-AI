"""Tests for :class:`anglerfish.integration.cowrie.AnglerfishOutput`."""

from __future__ import annotations

import asyncio
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from anglerfish.config import AnglerfishSettings
from anglerfish.forwarder import (
    Forwarder,
    ForwarderEvent,
    ForwardOutcome,
    JsonlSink,
)
from anglerfish.integration.cowrie import AnglerfishOutput


class _RecordingForwarder(Forwarder):
    """Test double that records every submitted event in memory."""

    def __init__(self, settings: AnglerfishSettings, *, tmp_path: Path) -> None:
        super().__init__(
            settings,
            jsonl_sink=JsonlSink(tmp_path / "fallback.jsonl"),
        )
        self.events: list[ForwarderEvent] = []

    async def submit(self, event: ForwarderEvent) -> ForwardOutcome:
        self.events.append(event)
        return ForwardOutcome.JSONL


async def test_submit_event_async(
    settings: AnglerfishSettings,
    tmp_path: Path,
) -> None:
    forwarder = _RecordingForwarder(settings, tmp_path=tmp_path)
    output = AnglerfishOutput(settings=settings, forwarder=forwarder)
    event: Mapping[str, Any] = {
        "eventid": "cowrie.command.input",
        "input": "ls /etc",
        "timestamp": "2026-05-22T12:34:56.000Z",
    }
    task = output.submit(event)
    assert isinstance(task, asyncio.Task)
    await task
    assert len(forwarder.events) == 1
    sent = forwarder.events[0]
    assert sent.event["eventid"] == "cowrie.command.input"
    assert sent.sourcetype == "cowrie:event"
    assert sent.time is not None


async def test_submit_event_without_timestamp_falls_back_to_now(
    settings: AnglerfishSettings,
    tmp_path: Path,
) -> None:
    forwarder = _RecordingForwarder(settings, tmp_path=tmp_path)
    output = AnglerfishOutput(settings=settings, forwarder=forwarder)
    task = output.submit({"eventid": "cowrie.session.connect", "src_ip": "1.1.1.1"})
    assert isinstance(task, asyncio.Task)
    await task
    assert forwarder.events[0].time is not None


async def test_submit_event_malformed_timestamp(
    settings: AnglerfishSettings,
    tmp_path: Path,
) -> None:
    forwarder = _RecordingForwarder(settings, tmp_path=tmp_path)
    output = AnglerfishOutput(settings=settings, forwarder=forwarder)
    task = output.submit({"eventid": "cowrie.session.input", "timestamp": "bogus"})
    assert isinstance(task, asyncio.Task)
    await task
    assert forwarder.events[0].time is not None  # falls back to "now"


def test_property_exposes_forwarder(
    settings: AnglerfishSettings,
    tmp_path: Path,
) -> None:
    forwarder = _RecordingForwarder(settings, tmp_path=tmp_path)
    output = AnglerfishOutput(settings=settings, forwarder=forwarder)
    assert output.forwarder is forwarder
