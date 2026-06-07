"""Tests for the wizard's Typer CLI."""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import HttpUrl
from rich.console import Console
from typer.testing import CliRunner

import anglerfish.wizard.__main__ as wizard_main
from anglerfish.wizard.__main__ import _prompt_console_password, app
from anglerfish.wizard.answers import WizardAnswers
from anglerfish.wizard.provision import OperatorAccount


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


def _answers(**overrides: object) -> WizardAnswers:
    base: dict[str, object] = {
        "terms_acknowledged": True,
        "bait_interface": "eth0",
        "service_interface": "eth1",
        "ollama_endpoint": HttpUrl("http://127.0.0.1:11434/"),
    }
    base.update(overrides)
    return WizardAnswers(**base)  # type: ignore[arg-type]


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
            "n",  # counter-deception decline (Stage 12)
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


def test_cli_provision_creates_account(
    runner: CliRunner,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """--provision drives the appliance provisioner with the console password."""
    captured: dict[str, object] = {}

    class _FakeSystemProvisioner:
        def __init__(self, **_: object) -> None:
            """Match SystemProvisioner's constructor; the kwargs are unused here."""

        def provision(self, account: OperatorAccount) -> Path | None:
            captured.update(
                username=account.username,
                console_password=account.console_password,
            )
            return None

    # SystemProvisioner runs useradd/chpasswd for real; swap it for a recorder
    # so the CLI path is exercised without root. Stub the hidden password prompt
    # so it does not contend with CliRunner's piped stdin.
    monkeypatch.setattr("anglerfish.wizard.wizard.SystemProvisioner", _FakeSystemProvisioner)
    monkeypatch.setattr(
        wizard_main,
        "_prompt_console_password",
        lambda _console, _answers: "rescue-pw",
    )

    target = tmp_path / "anglerfish.env"
    result = runner.invoke(
        app,
        [*_common_flags(tmp_path, target), "--provision"],
        input=_HAPPY_PATH_INPUTS,
    )
    assert result.exit_code == 0, result.output
    assert "Provisioned operator account: anglerfish-ops" in result.output
    assert captured["username"] == "anglerfish-ops"
    assert captured["console_password"] == "rescue-pw"


def test_prompt_console_password_returns_entered_value(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("anglerfish.wizard.__main__.Prompt.ask", lambda *_a, **_k: "hunter2")
    result = _prompt_console_password(Console(), _answers(operator_ssh_pubkey=None))
    assert result == "hunter2"


def test_prompt_console_password_warns_when_no_login_method(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr("anglerfish.wizard.__main__.Prompt.ask", lambda *_a, **_k: "")
    result = _prompt_console_password(Console(), _answers(operator_ssh_pubkey=None))
    assert result is None
    assert "no login method" in capsys.readouterr().out
