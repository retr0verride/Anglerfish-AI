"""Tests for the ASCII banner and the CLI entrypoint."""

from __future__ import annotations

import base64
import io

import pytest
from typer.testing import CliRunner

from anglerfish.cli.banner import BANNER, BANNER_LINES, render_banner, write_banner


def test_banner_constant_non_empty() -> None:
    assert BANNER
    assert BANNER.endswith("\n")
    assert "ANGLER" in BANNER.upper() or "█" in BANNER


def test_banner_lines_match_constant() -> None:
    assert "\n".join(BANNER_LINES) + "\n" == BANNER


def test_render_banner_without_color() -> None:
    out = render_banner(color=False)
    assert "\x1b[" not in out


def test_render_banner_with_color_inserts_escape() -> None:
    out = render_banner(color=True)
    assert "\x1b[1;36m" in out
    assert "\x1b[0m" in out


def test_write_banner_to_buffer_no_color() -> None:
    buf = io.StringIO()
    write_banner(buf, color=False)
    assert "\x1b[" not in buf.getvalue()
    assert buf.getvalue() == BANNER


def test_write_banner_autodetects_non_tty() -> None:
    buf = io.StringIO()  # isatty() returns False
    write_banner(buf)
    assert "\x1b[" not in buf.getvalue()


class _FakeTty(io.StringIO):
    def isatty(self) -> bool:
        return True


def test_write_banner_autodetects_tty() -> None:
    buf = _FakeTty()
    write_banner(buf)
    assert "\x1b[" in buf.getvalue()


# ---------------------------------------------------------------------------
# CLI entrypoint
# ---------------------------------------------------------------------------


def _runner() -> CliRunner:
    return CliRunner()


def test_cli_version() -> None:
    from anglerfish.cli.__main__ import app

    result = _runner().invoke(app, ["--version"])
    assert result.exit_code == 0
    assert "anglerfish-ai 0.1.0" in result.output


def test_cli_banner_command() -> None:
    from anglerfish.cli.__main__ import app

    result = _runner().invoke(app, ["banner", "--no-color"])
    assert result.exit_code == 0
    assert "ANGLER" in result.output.upper() or "█" in result.output


def test_cli_config_show_missing_required_exits_nonzero() -> None:
    from anglerfish.cli.__main__ import app

    result = _runner().invoke(app, ["config", "show"])
    assert result.exit_code == 2


def test_cli_config_show_success(monkeypatch: pytest.MonkeyPatch) -> None:
    from anglerfish.cli.__main__ import app

    monkeypatch.setenv("ANGLERFISH_DASHBOARD__SESSION_SECRET", "x" * 40)
    monkeypatch.setenv(
        "ANGLERFISH_CREDENTIALS__ENCRYPTION_KEY",
        base64.b64encode(b"\x00" * 32).decode("ascii"),
    )
    result = _runner().invoke(app, ["config", "show"])
    assert result.exit_code == 0
    assert "ollama" in result.output
    # Secrets must be masked in the dumped JSON.
    assert "x" * 40 not in result.output


def test_cli_no_args_shows_help() -> None:
    from anglerfish.cli.__main__ import app

    result = _runner().invoke(app, [])
    # Typer with no_args_is_help=True returns exit code 0 or 2 depending on
    # the click version; either way the help text should appear.
    assert "Anglerfish" in result.output
