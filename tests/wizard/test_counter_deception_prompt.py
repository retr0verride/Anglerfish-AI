"""Tests for the Stage 12 slice 12.5 counter-deception wizard prompt."""

from __future__ import annotations

from collections.abc import Callable, Iterator
from pathlib import Path

from pydantic import HttpUrl

from anglerfish.wizard import WizardAnswers, WizardPaths, prompt_for_answers, run_wizard
from anglerfish.wizard.counter_deception import COUNTER_DECEPTION_TERMS


def _make_prompter(
    *,
    confirms: list[bool],
    prompts: list[str],
) -> tuple[Callable[[str, str | None], str], Callable[[str, bool], bool]]:
    c_iter: Iterator[bool] = iter(confirms)
    p_iter: Iterator[str] = iter(prompts)

    def _prompt(_label: str, _default: str | None) -> str:
        return next(p_iter)

    def _confirm(_label: str, _default: bool) -> bool:
        return next(c_iter)

    return _prompt, _confirm


def _common_prompts() -> list[str]:
    return [
        "anglerfish-vm",
        "eth0",
        "eth1",
        "anglerfish-ops",
        "",  # operator_ssh_pubkey
        "admin",
        "",  # dashboard password (open mode)
        "http://127.0.0.1:11434/",
        "qwen3:14b",
        "srv-prod-01",
        "root",
        "",  # webhook
        "",  # maxmind
    ]


def test_terms_text_emitted_before_prompt() -> None:
    sink: list[str] = []
    # terms, bait DHCP, service DHCP, honeytokens-decline, counter-deception-decline.
    confirms = [True, True, True, False, False]
    _prompt, _confirm = _make_prompter(confirms=confirms, prompts=_common_prompts())
    prompt_for_answers(
        prompt=_prompt,
        confirm=_confirm,
        available_interfaces=[],
        output=sink.append,
    )
    joined = "".join(sink)
    assert "STAGE 12 ACTIVE COUNTER-DECEPTION NOTICE" in joined
    assert COUNTER_DECEPTION_TERMS.strip() in joined


def test_decline_leaves_disabled() -> None:
    confirms = [True, True, True, False, False]
    _prompt, _confirm = _make_prompter(confirms=confirms, prompts=_common_prompts())
    answers = prompt_for_answers(
        prompt=_prompt,
        confirm=_confirm,
        available_interfaces=[],
        output=lambda _s: None,
    )
    assert answers.counter_deception_enabled is False


def test_accept_enables() -> None:
    # terms, bait DHCP, service DHCP, honeytokens-decline, counter-deception-ACCEPT.
    confirms = [True, True, True, False, True]
    _prompt, _confirm = _make_prompter(confirms=confirms, prompts=_common_prompts())
    answers = prompt_for_answers(
        prompt=_prompt,
        confirm=_confirm,
        available_interfaces=[],
        output=lambda _s: None,
    )
    assert answers.counter_deception_enabled is True


def _paths(tmp_path: Path) -> WizardPaths:
    return WizardPaths(
        env_path=tmp_path / "anglerfish.env",
        bait_network_path=tmp_path / "systemd" / "10-bait.network",
        service_network_path=tmp_path / "systemd" / "20-service.network",
        hostname_path=tmp_path / "etc-hostname",
        hosts_path=tmp_path / "etc-hosts",
        ops_home=tmp_path / "ops-home",
    )


def _answers(*, counter_deception_enabled: bool) -> WizardAnswers:
    return WizardAnswers(
        terms_acknowledged=True,
        bait_interface="eth0",
        service_interface="eth1",
        ollama_endpoint=HttpUrl("http://127.0.0.1:11434/"),
        ollama_model="qwen3:14b",
        fake_hostname="srv-prod-01",
        fake_username="root",
        counter_deception_enabled=counter_deception_enabled,
    )


def test_writes_enabled_env_line_when_enabled(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    run_wizard(
        _answers(counter_deception_enabled=True),
        env_path=paths.env_path,
        paths=paths,
        run_preflight=False,
    )
    env = paths.env_path.read_text("utf-8")
    assert "ANGLERFISH_COUNTER_DECEPTION__ENABLED=true" in env


def test_omits_enabled_env_line_when_disabled(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    run_wizard(
        _answers(counter_deception_enabled=False),
        env_path=paths.env_path,
        paths=paths,
        run_preflight=False,
    )
    env = paths.env_path.read_text("utf-8")
    # The active ENABLED line is absent; only the commented placeholder remains.
    assert "\nANGLERFISH_COUNTER_DECEPTION__ENABLED=true" not in env
    assert "# ANGLERFISH_COUNTER_DECEPTION__ENABLED=" in env
