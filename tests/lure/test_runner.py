"""Tests for :func:`anglerfish.lure.runner.run_lure`."""

from __future__ import annotations

import asyncio
import base64
import ipaddress
import logging
import os
from pathlib import Path

import pytest
from pydantic import SecretStr

from anglerfish.config import AnglerfishSettings
from anglerfish.config.models import CredentialsConfig, DashboardConfig
from anglerfish.lure.config import LureConfig
from anglerfish.lure.runner import run_lure

pytestmark = pytest.mark.skipif(
    os.name == "nt",
    reason="runner uses POSIX signal-handler wiring",
)


def _settings(
    *,
    lure: LureConfig,
    session_secret: str,
    encryption_key_b64: str,
    credentials_db_path: Path | None = None,
) -> AnglerfishSettings:
    cred_kwargs: dict[str, object] = {
        "encryption_key": SecretStr(encryption_key_b64),
    }
    if credentials_db_path is not None:
        cred_kwargs["database_path"] = credentials_db_path
    return AnglerfishSettings(
        dashboard=DashboardConfig(session_secret=SecretStr(session_secret)),
        credentials=CredentialsConfig(**cred_kwargs),  # type: ignore[arg-type]
        lure=lure,
    )


async def test_run_lure_skips_when_disabled(
    tmp_path: Path,
    session_secret: str,
    encryption_key_b64: str,
    caplog: pytest.LogCaptureFixture,
) -> None:
    lure_cfg = LureConfig(enabled=False, host_key_dir=tmp_path / "keys")
    settings = _settings(
        lure=lure_cfg,
        session_secret=session_secret,
        encryption_key_b64=encryption_key_b64,
    )
    with caplog.at_level(logging.WARNING, logger="anglerfish.lure.runner"):
        await asyncio.wait_for(run_lure(settings), timeout=2.0)
    assert any("ENABLED=false" in r.message for r in caplog.records)


async def test_run_lure_returns_cleanly_on_shutdown_event(
    tmp_path: Path,
    session_secret: str,
    encryption_key_b64: str,
) -> None:
    """Smoke test: start the runner, signal shutdown, expect clean exit.

    We cannot easily send SIGTERM to the test process; instead, the
    runner's shutdown is an asyncio.Event. We trigger it by patching
    the signal-handler wire so we own the Event object directly, then
    set it from a background task after start completes.
    """
    from anglerfish.lure import runner as runner_mod

    lure_cfg = LureConfig(
        enabled=True,
        listen_host=ipaddress.IPv4Address("127.0.0.1"),
        listen_port=0,  # ephemeral
        host_key_dir=tmp_path / "keys",
        keepalive_interval_s=0,
    )
    # Use a credentials encryption key derived from a fixed seed so
    # the store opens cleanly.
    encryption_key = base64.b64encode(b"\x07" * 32).decode("ascii")
    settings = _settings(
        lure=lure_cfg,
        session_secret=session_secret,
        encryption_key_b64=encryption_key,
        credentials_db_path=tmp_path / "creds.db",
    )

    captured: dict[str, asyncio.Event] = {}
    original = runner_mod._install_signal_handlers

    def capture(event: asyncio.Event) -> None:
        captured["event"] = event
        original(event)

    runner_mod._install_signal_handlers = capture  # type: ignore[assignment]
    try:
        runner_task = asyncio.create_task(run_lure(settings))
        # Poll briefly for the shutdown event to be installed.
        for _ in range(50):
            await asyncio.sleep(0.05)
            if "event" in captured:
                break
        assert "event" in captured, "runner did not install the shutdown event"
        # Set the event to request graceful shutdown.
        captured["event"].set()
        await asyncio.wait_for(runner_task, timeout=5.0)
    finally:
        runner_mod._install_signal_handlers = original
