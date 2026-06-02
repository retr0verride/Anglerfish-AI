"""Tests for the ``anglerfish callback serve`` typer subcommand guard.

The receiver refuses to start when ``honeytokens.enabled`` is False: with
the feature off it would log every inbound callback as a miss, so the
subcommand exits 2 with a structured panel before binding a socket. That
guard runs before uvicorn, so it is unit-testable via CliRunner.
"""

from __future__ import annotations

import base64
from pathlib import Path

import pytest
from typer.testing import CliRunner

from anglerfish.cli.__main__ import app

# Wide, colorless terminal so the Rich panel text is not wrapped/styled
# (matches the dashboard subcommand tests).
_HELP_ENV = {"COLUMNS": "200", "NO_COLOR": "1", "TERM": "dumb"}


@pytest.fixture
def env_setup(
    tmp_path: Path,
    session_secret: str,
    monkeypatch: pytest.MonkeyPatch,
) -> Path:
    """Minimal env so load_settings succeeds for the callback subcommand."""
    monkeypatch.setenv("ANGLERFISH_DASHBOARD__SESSION_SECRET", session_secret)
    monkeypatch.setenv(
        "ANGLERFISH_CREDENTIALS__ENCRYPTION_KEY",
        base64.b64encode(b"\x09" * 32).decode("ascii"),
    )
    monkeypatch.setenv("ANGLERFISH_SESSIONS__DATABASE_PATH", str(tmp_path / "sessions.db"))
    return tmp_path


def test_callback_serve_refuses_when_honeytokens_disabled(
    env_setup: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ANGLERFISH_HONEYTOKENS__ENABLED", "false")
    runner = CliRunner()
    result = runner.invoke(app, ["callback", "serve"], env=_HELP_ENV)
    assert result.exit_code == 2
    assert "Honeytokens disabled" in result.output
