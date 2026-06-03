"""CLI wiring for the audit-log shipper (TODO-12)."""

from __future__ import annotations

import base64
from pathlib import Path

import pytest
from typer.testing import CliRunner

from anglerfish.cli.__main__ import app

_HELP_ENV = {"COLUMNS": "200", "NO_COLOR": "1", "TERM": "dumb"}


@pytest.fixture
def env_setup(
    tmp_path: Path,
    session_secret: str,
    monkeypatch: pytest.MonkeyPatch,
) -> Path:
    """Minimal env so load_settings succeeds for the audit subcommand."""
    monkeypatch.setenv("ANGLERFISH_DASHBOARD__SESSION_SECRET", session_secret)
    monkeypatch.setenv(
        "ANGLERFISH_CREDENTIALS__ENCRYPTION_KEY",
        base64.b64encode(b"\x09" * 32).decode("ascii"),
    )
    monkeypatch.setenv("ANGLERFISH_SESSIONS__DATABASE_PATH", str(tmp_path / "sessions.db"))
    return tmp_path


def test_top_level_help_lists_audit_group() -> None:
    result = CliRunner().invoke(app, ["--help"], env=_HELP_ENV)
    assert result.exit_code == 0
    assert "audit" in result.output


def test_audit_help_lists_ship_subcommand() -> None:
    result = CliRunner().invoke(app, ["audit", "--help"], env=_HELP_ENV)
    assert result.exit_code == 0
    assert "ship" in result.output


def test_audit_ship_is_noop_when_disabled(env_setup: Path) -> None:
    # Default config has no shipper URL: the command must exit 0 with a
    # clear "disabled" notice rather than starting the loop.
    env = {**_HELP_ENV}
    result = CliRunner().invoke(app, ["audit", "ship"], env=env)
    assert result.exit_code == 0
    assert "disabled" in result.output.lower()
