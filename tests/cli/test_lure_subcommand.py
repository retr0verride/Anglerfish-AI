"""Tests for the ``anglerfish lure`` typer subcommand."""

from __future__ import annotations

import base64
import os
from pathlib import Path

import pytest
from typer.testing import CliRunner

from anglerfish.cli.__main__ import app


@pytest.fixture
def env_setup(
    tmp_path: Path,
    session_secret: str,
    monkeypatch: pytest.MonkeyPatch,
) -> Path:
    """Set the env so load_settings succeeds and the lure binds to loopback."""
    monkeypatch.setenv("ANGLERFISH_DASHBOARD__SESSION_SECRET", session_secret)
    monkeypatch.setenv(
        "ANGLERFISH_CREDENTIALS__ENCRYPTION_KEY",
        base64.b64encode(b"\x09" * 32).decode("ascii"),
    )
    monkeypatch.setenv("ANGLERFISH_LURE__HOST_KEY_DIR", str(tmp_path / "keys"))
    monkeypatch.setenv("ANGLERFISH_LURE__LISTEN_HOST", "127.0.0.1")
    monkeypatch.setenv("ANGLERFISH_LURE__LISTEN_PORT", "0")
    return tmp_path


def test_validate_config_exits_zero_for_valid_setup(env_setup: Path) -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["lure", "validate-config"])
    assert result.exit_code == 0, result.output
    assert "lure config OK" in result.output


def test_validate_config_exits_nonzero_for_unspecified_host(
    env_setup: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ANGLERFISH_LURE__LISTEN_HOST", "0.0.0.0")
    runner = CliRunner()
    result = runner.invoke(app, ["lure", "validate-config"])
    assert result.exit_code == 2
    assert "unspecified" in result.output.lower() or "bait-NIC" in result.output


def test_validate_config_zero_when_disabled(
    env_setup: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ANGLERFISH_LURE__ENABLED", "false")
    runner = CliRunner()
    result = runner.invoke(app, ["lure", "validate-config"])
    assert result.exit_code == 0
    assert "would not bind" in result.output


@pytest.mark.skipif(os.name == "nt", reason="bait-NIC test-bind uses POSIX errno semantics")
def test_validate_config_rejects_unassigned_ip(
    env_setup: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # 198.51.100.x is RFC 5737 documentation range; not on any iface.
    monkeypatch.setenv("ANGLERFISH_LURE__LISTEN_HOST", "198.51.100.42")
    runner = CliRunner()
    result = runner.invoke(app, ["lure", "validate-config"])
    assert result.exit_code == 2
    assert "bait-NIC" in result.output or "not assigned" in result.output


def test_lure_serve_help_lists_under_lure_group(env_setup: Path) -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["lure", "--help"])
    assert result.exit_code == 0
    assert "serve" in result.output
    assert "validate-config" in result.output
