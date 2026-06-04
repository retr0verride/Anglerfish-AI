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
from anglerfish.lure.runner import (
    _effective_lure_config,
    _resolve_interface_ipv4,
    run_lure,
)

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


# ---------------------------------------------------------------------------
# DHCP bait-NIC binding: lure resolves the bait interface's current IPv4 when
# listen_host is unset (the wizard cannot set a static IP for a DHCP NIC).
# ---------------------------------------------------------------------------


def _settings_iface(
    *,
    lure: LureConfig,
    session_secret: str,
    encryption_key_b64: str,
    bait_interface: str | None,
) -> AnglerfishSettings:
    return AnglerfishSettings(
        dashboard=DashboardConfig(session_secret=SecretStr(session_secret)),
        credentials=CredentialsConfig(encryption_key=SecretStr(encryption_key_b64)),
        lure=lure,
        bait_interface=bait_interface,
    )


def test_resolve_interface_ipv4_loopback() -> None:
    # The loopback interface always carries 127.0.0.1 on Linux.
    assert _resolve_interface_ipv4("lo") == "127.0.0.1"


def test_resolve_interface_ipv4_unknown_returns_none() -> None:
    assert _resolve_interface_ipv4("does-not-exist0") is None


def test_resolve_interface_ipv4_empty_returns_none() -> None:
    assert _resolve_interface_ipv4("") is None


def test_effective_lure_config_static_listen_host_unchanged(
    tmp_path: Path, session_secret: str, encryption_key_b64: str
) -> None:
    lure = LureConfig(listen_host="127.0.0.1", host_key_dir=tmp_path / "k")  # type: ignore[arg-type]
    settings = _settings_iface(
        lure=lure,
        session_secret=session_secret,
        encryption_key_b64=encryption_key_b64,
        bait_interface="lo",
    )
    # An explicit (static) listen_host is never overridden.
    assert _effective_lure_config(settings) is settings.lure


def test_effective_lure_config_dhcp_resolves_interface_ip(
    tmp_path: Path, session_secret: str, encryption_key_b64: str
) -> None:
    lure = LureConfig(host_key_dir=tmp_path / "k")  # listen_host defaults to 0.0.0.0
    settings = _settings_iface(
        lure=lure,
        session_secret=session_secret,
        encryption_key_b64=encryption_key_b64,
        bait_interface="lo",
    )
    effective = _effective_lure_config(settings)
    assert str(effective.listen_host) == "127.0.0.1"


def test_effective_lure_config_unresolvable_interface_left_unchanged(
    tmp_path: Path, session_secret: str, encryption_key_b64: str
) -> None:
    lure = LureConfig(host_key_dir=tmp_path / "k")  # 0.0.0.0
    settings = _settings_iface(
        lure=lure,
        session_secret=session_secret,
        encryption_key_b64=encryption_key_b64,
        bait_interface="does-not-exist0",
    )
    effective = _effective_lure_config(settings)
    # Still unspecified -> validate_bait_nic rejects and systemd retries.
    assert effective.listen_host.is_unspecified


def test_effective_lure_config_no_bait_interface_unchanged(
    tmp_path: Path, session_secret: str, encryption_key_b64: str
) -> None:
    lure = LureConfig(host_key_dir=tmp_path / "k")  # 0.0.0.0
    settings = _settings_iface(
        lure=lure,
        session_secret=session_secret,
        encryption_key_b64=encryption_key_b64,
        bait_interface=None,
    )
    assert _effective_lure_config(settings) is settings.lure
