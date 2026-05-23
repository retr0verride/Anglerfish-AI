"""Tests for :class:`anglerfish.forwarder.Forwarder`."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import httpx
import pytest
from pydantic import HttpUrl, SecretStr

from anglerfish.config import AnglerfishSettings
from anglerfish.config.models import (
    CredentialsConfig,
    DashboardConfig,
    SplunkConfig,
)
from anglerfish.forwarder import (
    Forwarder,
    ForwarderEvent,
    ForwardOutcome,
    JsonlSink,
    SplunkHECClient,
)


def _settings_with_splunk(
    enabled: bool,
    *,
    tmp_path: Path,
    session_secret: str,
    encryption_key_b64: str,
) -> AnglerfishSettings:
    if enabled:
        splunk = SplunkConfig(
            enabled=True,
            hec_url=HttpUrl("https://splunk.test:8088/services/collector/event"),
            hec_token=SecretStr("test-token"),
            fallback_path=tmp_path / "fallback.jsonl",
        )
    else:
        splunk = SplunkConfig(fallback_path=tmp_path / "fallback.jsonl")
    return AnglerfishSettings(
        dashboard=DashboardConfig(session_secret=SecretStr(session_secret)),
        credentials=CredentialsConfig(encryption_key=SecretStr(encryption_key_b64)),
        splunk=splunk,
    )


def _hec_client(
    cfg: SplunkConfig,
    handler: Callable[[httpx.Request], httpx.Response],
) -> SplunkHECClient:
    transport = httpx.MockTransport(handler)
    return SplunkHECClient(cfg, http_client=httpx.AsyncClient(transport=transport))


async def test_submit_succeeds_via_hec(
    tmp_path: Path,
    session_secret: str,
    encryption_key_b64: str,
) -> None:
    settings = _settings_with_splunk(
        True,
        tmp_path=tmp_path,
        session_secret=session_secret,
        encryption_key_b64=encryption_key_b64,
    )

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"code": 0})

    forwarder = Forwarder(
        settings,
        hec_client=_hec_client(settings.splunk, handler),
    )
    try:
        outcome = await forwarder.submit(ForwarderEvent(event={"x": 1}))
    finally:
        await forwarder.aclose()
    assert outcome == ForwardOutcome.HEC
    assert not (tmp_path / "fallback.jsonl").exists()


async def test_submit_falls_back_to_jsonl_on_hec_failure(
    tmp_path: Path,
    session_secret: str,
    encryption_key_b64: str,
) -> None:
    settings = _settings_with_splunk(
        True,
        tmp_path=tmp_path,
        session_secret=session_secret,
        encryption_key_b64=encryption_key_b64,
    )

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(503, text="overloaded")

    forwarder = Forwarder(
        settings,
        hec_client=_hec_client(settings.splunk, handler),
    )
    try:
        outcome = await forwarder.submit(ForwarderEvent(event={"x": 1}))
    finally:
        await forwarder.aclose()
    assert outcome == ForwardOutcome.JSONL
    assert (tmp_path / "fallback.jsonl").exists()


async def test_submit_uses_jsonl_when_splunk_disabled(
    tmp_path: Path,
    session_secret: str,
    encryption_key_b64: str,
) -> None:
    settings = _settings_with_splunk(
        False,
        tmp_path=tmp_path,
        session_secret=session_secret,
        encryption_key_b64=encryption_key_b64,
    )
    forwarder = Forwarder(settings)
    try:
        outcome = await forwarder.submit(ForwarderEvent(event={"y": 2}))
    finally:
        await forwarder.aclose()
    assert outcome == ForwardOutcome.JSONL
    assert (tmp_path / "fallback.jsonl").exists()
    assert forwarder.hec_client is None


async def test_submit_reports_dropped_when_both_backends_fail(
    tmp_path: Path,
    session_secret: str,
    encryption_key_b64: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = _settings_with_splunk(
        True,
        tmp_path=tmp_path,
        session_secret=session_secret,
        encryption_key_b64=encryption_key_b64,
    )

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(503)

    from anglerfish.forwarder.errors import JsonlWriteError
    from anglerfish.forwarder.jsonl import JsonlSink as _JsonlSink

    async def _failing_write(self: object, record: object) -> None:
        raise JsonlWriteError("simulated")

    monkeypatch.setattr(_JsonlSink, "write", _failing_write)

    forwarder = Forwarder(
        settings,
        hec_client=_hec_client(settings.splunk, handler),
    )
    try:
        outcome = await forwarder.submit(ForwarderEvent(event={"x": 1}))
    finally:
        await forwarder.aclose()
    assert outcome == ForwardOutcome.DROPPED


async def test_forwarder_properties(
    tmp_path: Path,
    session_secret: str,
    encryption_key_b64: str,
) -> None:
    settings = _settings_with_splunk(
        False,
        tmp_path=tmp_path,
        session_secret=session_secret,
        encryption_key_b64=encryption_key_b64,
    )
    sink = JsonlSink(tmp_path / "explicit.jsonl")
    forwarder = Forwarder(settings, jsonl_sink=sink)
    assert forwarder.settings is settings
    assert forwarder.jsonl_sink is sink
    assert forwarder.hec_client is None
    await forwarder.aclose()


async def test_async_context_manager(
    tmp_path: Path,
    session_secret: str,
    encryption_key_b64: str,
) -> None:
    settings = _settings_with_splunk(
        False,
        tmp_path=tmp_path,
        session_secret=session_secret,
        encryption_key_b64=encryption_key_b64,
    )
    async with Forwarder(settings) as forwarder:
        outcome = await forwarder.submit(ForwarderEvent(event={"z": 3}))
    assert outcome == ForwardOutcome.JSONL
