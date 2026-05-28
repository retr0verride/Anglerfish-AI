"""Tests for the ``anglerfish dashboard serve`` typer subcommand.

Closes pre-deploy sweep TODO-2: the previous systemd unit invoked
``uvicorn --factory anglerfish.dashboard.app:create_app``, but the
factory requires a positional ``settings`` argument so every clean
install since Stage 4 failed to start. The subcommand owns its own
uvicorn instance + loads settings explicitly so config errors
surface as a structured panel + clean exit 2 rather than a
factory-call traceback in journalctl.
"""

from __future__ import annotations

import base64
from pathlib import Path

import pytest
from typer.testing import CliRunner

from anglerfish.cli.__main__ import app

# Typer + Rich render help inside a panel sized to the terminal width.
# CI runs the gates without a TTY so the default width (~80 cols)
# wraps long option-help strings across lines and renders ANSI styling
# that fragments substring searches like "--host". Force a wide,
# colorless terminal so the help output stays deterministic across
# local + CI environments.
_HELP_ENV = {"COLUMNS": "200", "NO_COLOR": "1", "TERM": "dumb"}


@pytest.fixture
def env_setup(
    tmp_path: Path,
    session_secret: str,
    monkeypatch: pytest.MonkeyPatch,
) -> Path:
    """Minimal env so load_settings succeeds for the dashboard subcommand."""
    monkeypatch.setenv("ANGLERFISH_DASHBOARD__SESSION_SECRET", session_secret)
    monkeypatch.setenv(
        "ANGLERFISH_CREDENTIALS__ENCRYPTION_KEY",
        base64.b64encode(b"\x09" * 32).decode("ascii"),
    )
    monkeypatch.setenv("ANGLERFISH_SESSIONS__DATABASE_PATH", str(tmp_path / "sessions.db"))
    return tmp_path


def test_dashboard_help_lists_serve_subcommand(env_setup: Path) -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["dashboard", "--help"], env=_HELP_ENV)
    assert result.exit_code == 0
    assert "serve" in result.output


def test_dashboard_serve_help_shows_options(env_setup: Path) -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["dashboard", "serve", "--help"], env=_HELP_ENV)
    assert result.exit_code == 0
    assert "--host" in result.output
    assert "--port" in result.output


def test_dashboard_serve_exits_2_on_invalid_config(
    env_setup: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A bad config surfaces as a structured Console panel + clean exit 2.

    Closes the previously-broken ``--factory`` invocation path:
    that path raised TypeError inside uvicorn's worker which surfaced
    as a traceback rather than a clean exit. The subcommand pattern
    catches ValidationError at the top-level + reports through
    typer.Exit(2) the same way ``bridge serve`` does.
    """
    monkeypatch.setenv("ANGLERFISH_DASHBOARD__PORT", "999999")  # out of [1, 65535]
    runner = CliRunner()
    result = runner.invoke(app, ["dashboard", "serve"], env=_HELP_ENV)
    assert result.exit_code == 2
    assert "Configuration error" in result.output


def test_dashboard_top_level_help_lists_dashboard_group(env_setup: Path) -> None:
    """The dashboard typer subgroup is registered on the root app."""
    runner = CliRunner()
    result = runner.invoke(app, ["--help"], env=_HELP_ENV)
    assert result.exit_code == 0
    assert "dashboard" in result.output
