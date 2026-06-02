"""Unit tests for the lure's bridge-routing handlers.

Drives ``_handle_bridge_stream`` / ``_handle_bridge_buffered`` with a
minimal fake container + a real :class:`LureSessionContext`, focusing on
the cwd-sync behaviour (audit review M1): a bridge-handled ``cd`` must
update the session's working directory so the prompt and native handlers
do not drift.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from types import SimpleNamespace
from typing import cast
from uuid import uuid4

from anglerfish.lure.bridge_client import BridgeStreamChunk, BufferedCommandResult
from anglerfish.lure.server import (
    LureServer,
    _handle_bridge_buffered,
    _handle_bridge_stream,
)
from anglerfish.lure.session import LureSessionContext


def _session() -> LureSessionContext:
    return LureSessionContext(
        uuid4(),
        source_ip="203.0.113.5",
        username="root",
        hostname="box",
        cwd="/home/root",
    )


def _container(bridge_client: object) -> LureServer:
    # The handlers only touch .bridge_client / .commands / .audit; a
    # SimpleNamespace stub is enough. Cast so the handler signatures
    # (which expect LureServer) type-check.
    return cast(
        "LureServer",
        SimpleNamespace(
            bridge_client=bridge_client,
            commands=SimpleNamespace(record_bridge_latency=lambda _ms: None),
            audit=SimpleNamespace(record=lambda *_a, **_k: None),
        ),
    )


async def test_bridge_stream_applies_terminal_cwd_to_session() -> None:
    session = _session()
    writes: list[str] = []

    async def _stream(
        _uuid: object,
        _cmd: str,
        *,
        fs_context: str | None = None,
    ) -> AsyncIterator[BridgeStreamChunk]:
        yield BridgeStreamChunk(delta="bin  etc  tmp", source="ai", done=False)
        yield BridgeStreamChunk(
            delta="",
            source="ai",
            done=True,
            latency_ms=4.0,
            cwd="/var/www",
        )

    await _handle_bridge_stream(
        _container(SimpleNamespace(command_stream=_stream)),
        session,
        "cd /var/www && ls",
        writes.append,
    )
    assert session.cwd == "/var/www"


async def test_bridge_stream_keeps_cwd_when_bridge_reports_none() -> None:
    session = _session()

    async def _stream(
        _uuid: object,
        _cmd: str,
        *,
        fs_context: str | None = None,
    ) -> AsyncIterator[BridgeStreamChunk]:
        yield BridgeStreamChunk(delta="hi", source="ai", done=True)

    await _handle_bridge_stream(
        _container(SimpleNamespace(command_stream=_stream)),
        session,
        "echo hi",
        lambda _s: None,
    )
    assert session.cwd == "/home/root"


async def test_bridge_buffered_applies_returned_cwd_to_session() -> None:
    session = _session()
    writes: list[str] = []

    async def _submit(
        _uuid: object,
        _cmd: str,
        *,
        fs_context: str | None = None,
    ) -> BufferedCommandResult:
        return BufferedCommandResult(text="ok\n", cwd="/var/log")

    await _handle_bridge_buffered(
        _container(SimpleNamespace(submit_command=_submit)),
        session,
        "cd /var/log",
        writes.append,
    )
    assert session.cwd == "/var/log"
