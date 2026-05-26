"""Tests for the wizard's Typer CLI."""

from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from anglerfish.wizard.__main__ import app


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


_HAPPY_PATH_INPUTS = (
    "\n".join(
        [
            "y",  # accept terms
            "anglerfish-vm",  # vm hostname
            "eth0",  # bait
            "eth1",  # service
            "y",  # bait DHCP yes
            "y",  # service DHCP yes
            "anglerfish-ops",  # operator user
            "",  # ssh key blank
            "admin",  # dashboard admin user
            "",  # dashboard password (open mode)
            "http://127.0.0.1:11434/",  # ollama URL
            "qwen3:14b",  # model
            "srv-prod-01",  # fake host
            "root",  # fake user
            "",  # webhook empty
            "",  # MaxMind licence key empty
            "n",  # honeytokens decline (Stage 11)
        ],
    )
    + "\n"
)


def _common_flags(tmp_path: Path, target: Path) -> list[str]:
    """Return CLI flags that redirect every system path under tmp_path."""
    return [
        "--env",
        str(target),
        "--no-banner",
        "--skip-preflight",
        "--systemd-network-dir",
        str(tmp_path / "systemd"),
        "--hostname-path",
        str(tmp_path / "etc-hostname"),
        "--hosts-path",
        str(tmp_path / "etc-hosts"),
        "--ops-home",
        str(tmp_path / "ops-home"),
    ]


def test_cli_writes_env_with_scripted_input(
    runner: CliRunner,
    tmp_path: Path,
) -> None:
    target = tmp_path / "anglerfish.env"
    result = runner.invoke(
        app,
        _common_flags(tmp_path, target),
        input=_HAPPY_PATH_INPUTS,
    )
    assert result.exit_code == 0, result.output
    assert target.exists()
    content = target.read_text("utf-8")
    assert "ANGLERFISH_OLLAMA__BASE_URL=http://127.0.0.1:11434/" in content


def test_cli_declined_terms_exits_2(runner: CliRunner, tmp_path: Path) -> None:
    target = tmp_path / "anglerfish.env"
    result = runner.invoke(
        app,
        _common_flags(tmp_path, target),
        input="n\n",
    )
    assert result.exit_code == 2
    assert not target.exists()


def test_cli_value_error_exits_1(runner: CliRunner, tmp_path: Path) -> None:
    target = tmp_path / "anglerfish.env"
    inputs = (
        "\n".join(
            [
                "y",
                "anglerfish-vm",
                "eth0",
                "eth1",
                "y",  # bait DHCP
                "y",  # service DHCP
                "anglerfish-ops",
                "",
                "admin",  # dashboard admin user
                "",  # dashboard password
                "not-a-url",
            ],
        )
        + "\n"
    )
    result = runner.invoke(
        app,
        _common_flags(tmp_path, target),
        input=inputs,
    )
    assert result.exit_code == 1


def test_cli_reconfigure_uses_saved_answers(
    runner: CliRunner,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """First-boot writes wizard.json; --reconfigure reads it as defaults."""
    target = tmp_path / "anglerfish.env"
    saved_path = tmp_path / "wizard.json"

    monkeypatch.setattr(
        "anglerfish.wizard.__main__.DEFAULT_ANSWERS_PATH",
        saved_path,
    )

    first = runner.invoke(
        app,
        _common_flags(tmp_path, target),
        input=_HAPPY_PATH_INPUTS,
    )
    assert first.exit_code == 0, first.output
    assert saved_path.exists()

    reconfigure_inputs = "y\n" + "\n" * 20
    second = runner.invoke(
        app,
        [*_common_flags(tmp_path, target), "--reconfigure"],
        input=reconfigure_inputs,
    )
    assert second.exit_code == 0, second.output
    assert (
        "secrets were regenerated" in second.output.lower() or "regenerate" in second.output.lower()
    )


def test_cli_reconfigure_without_saved_file_warns_but_proceeds(
    runner: CliRunner,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "anglerfish.wizard.__main__.DEFAULT_ANSWERS_PATH",
        tmp_path / "absent.json",
    )
    target = tmp_path / "anglerfish.env"
    result = runner.invoke(
        app,
        [*_common_flags(tmp_path, target), "--reconfigure"],
        input=_HAPPY_PATH_INPUTS,
    )
    assert result.exit_code == 0, result.output
    assert "no prior answers" in result.output.lower()


def test_cli_reconfigure_corrupt_save_file_exits_1(
    runner: CliRunner,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    saved = tmp_path / "wizard.json"
    saved.write_text("{not valid", encoding="utf-8")
    monkeypatch.setattr(
        "anglerfish.wizard.__main__.DEFAULT_ANSWERS_PATH",
        saved,
    )
    target = tmp_path / "anglerfish.env"
    result = runner.invoke(
        app,
        [*_common_flags(tmp_path, target), "--reconfigure"],
        input="",
    )
    assert result.exit_code == 1
