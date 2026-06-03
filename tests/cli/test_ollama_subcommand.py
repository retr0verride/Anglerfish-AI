"""CLI wiring for the first-boot model pull (TODO-14)."""

from __future__ import annotations

from typer.testing import CliRunner

from anglerfish.cli.__main__ import app

_HELP_ENV = {"COLUMNS": "200", "NO_COLOR": "1", "TERM": "dumb"}


def test_top_level_help_lists_ollama_group() -> None:
    result = CliRunner().invoke(app, ["--help"], env=_HELP_ENV)
    assert result.exit_code == 0
    assert "ollama" in result.output


def test_ollama_help_lists_pull_subcommand() -> None:
    result = CliRunner().invoke(app, ["ollama", "--help"], env=_HELP_ENV)
    assert result.exit_code == 0
    assert "pull" in result.output
