"""Tests for the Stage 11 slice 11.4 honeytoken wizard prompt."""

from __future__ import annotations

from collections.abc import Callable, Iterator

import pytest

from anglerfish.wizard import prompt_for_answers
from anglerfish.wizard.honeytokens import HONEYTOKENS_TERMS


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
    """Prompts the wizard always asks before the honeytokens step."""
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


def test_honeytokens_terms_text_emitted_before_prompt() -> None:
    """The wizard outputs the acknowledgement text before the confirm."""
    sink: list[str] = []
    # confirms: terms, bait DHCP, service DHCP, honeytokens-decline,
    # counter-deception-decline (Stage 12 added the 5th prompt).
    confirms = [True, True, True, False, False]
    _prompt, _confirm = _make_prompter(confirms=confirms, prompts=_common_prompts())

    prompt_for_answers(
        prompt=_prompt,
        confirm=_confirm,
        available_interfaces=[],
        output=sink.append,
    )
    joined = "".join(sink)
    assert "STAGE 11 HONEYTOKEN DEPLOYMENT NOTICE" in joined
    # And the text shipped is the canonical constant, not a stale copy.
    assert HONEYTOKENS_TERMS.strip() in joined


def test_honeytokens_decline_leaves_disabled() -> None:
    # confirms: terms, bait DHCP, service DHCP, honeytokens-decline,
    # counter-deception-decline (Stage 12).
    confirms = [True, True, True, False, False]
    _prompt, _confirm = _make_prompter(confirms=confirms, prompts=_common_prompts())
    answers = prompt_for_answers(
        prompt=_prompt,
        confirm=_confirm,
        available_interfaces=[],
        output=lambda _s: None,
    )
    assert answers.honeytokens_enabled is False
    assert answers.honeytokens_callback_base_url is None


def test_honeytokens_accept_requires_url_prompt() -> None:
    # confirms: terms, bait DHCP, service DHCP, honeytokens-accept,
    # counter-deception-decline (Stage 12).
    confirms = [True, True, True, True, False]
    # The URL prompt fires AFTER all common prompts.
    prompts = [*_common_prompts(), "https://honey.example.com"]
    _prompt, _confirm = _make_prompter(confirms=confirms, prompts=prompts)
    answers = prompt_for_answers(
        prompt=_prompt,
        confirm=_confirm,
        available_interfaces=[],
        output=lambda _s: None,
    )
    assert answers.honeytokens_enabled is True
    assert answers.honeytokens_callback_base_url is not None
    assert str(answers.honeytokens_callback_base_url).startswith("https://")


def test_honeytokens_accept_with_blank_url_raises() -> None:
    confirms = [True, True, True, True]
    prompts = [*_common_prompts(), ""]
    _prompt, _confirm = _make_prompter(confirms=confirms, prompts=prompts)
    with pytest.raises(ValueError, match="no callback_base_url"):
        prompt_for_answers(
            prompt=_prompt,
            confirm=_confirm,
            available_interfaces=[],
            output=lambda _s: None,
        )


def test_honeytokens_accept_with_http_url_raises() -> None:
    """Plaintext HTTP URLs are rejected; the wizard enforces HTTPS."""
    confirms = [True, True, True, True]
    prompts = [*_common_prompts(), "http://honey.example.com"]  # devskim: ignore DS137138
    _prompt, _confirm = _make_prompter(confirms=confirms, prompts=prompts)
    with pytest.raises(ValueError, match="https"):
        prompt_for_answers(
            prompt=_prompt,
            confirm=_confirm,
            available_interfaces=[],
            output=lambda _s: None,
        )


def test_honeytokens_writes_env_lines_when_enabled(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """run_wizard emits ANGLERFISH_HONEYTOKENS__* lines when enabled."""
    from anglerfish.wizard import WizardAnswers, WizardPaths, run_wizard

    paths = WizardPaths(
        env_path=tmp_path / "anglerfish.env",
        bait_network_path=tmp_path / "systemd" / "10-bait.network",
        service_network_path=tmp_path / "systemd" / "20-service.network",
        hostname_path=tmp_path / "etc-hostname",
        hosts_path=tmp_path / "etc-hosts",
        ops_home=tmp_path / "ops-home",
    )
    from pydantic import HttpUrl

    answers = WizardAnswers(
        terms_acknowledged=True,
        bait_interface="eth0",
        service_interface="eth1",
        ollama_endpoint=HttpUrl("http://127.0.0.1:11434/"),
        ollama_model="qwen3:14b",
        fake_hostname="srv-prod-01",
        fake_username="root",
        honeytokens_enabled=True,
        honeytokens_callback_base_url=HttpUrl("https://honey.example.com"),
    )
    run_wizard(answers, env_path=paths.env_path, paths=paths, run_preflight=False)
    env = paths.env_path.read_text("utf-8")
    assert "ANGLERFISH_HONEYTOKENS__ENABLED=true" in env
    assert "ANGLERFISH_HONEYTOKENS__CALLBACK_BASE_URL=https://honey.example.com" in env


def test_honeytokens_omits_env_lines_when_disabled(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """run_wizard skips both ANGLERFISH_HONEYTOKENS__* lines when disabled."""
    from pydantic import HttpUrl

    from anglerfish.wizard import WizardAnswers, WizardPaths, run_wizard

    paths = WizardPaths(
        env_path=tmp_path / "anglerfish.env",
        bait_network_path=tmp_path / "systemd" / "10-bait.network",
        service_network_path=tmp_path / "systemd" / "20-service.network",
        hostname_path=tmp_path / "etc-hostname",
        hosts_path=tmp_path / "etc-hosts",
        ops_home=tmp_path / "ops-home",
    )
    answers = WizardAnswers(
        terms_acknowledged=True,
        bait_interface="eth0",
        service_interface="eth1",
        ollama_endpoint=HttpUrl("http://127.0.0.1:11434/"),
        ollama_model="qwen3:14b",
        fake_hostname="srv-prod-01",
        fake_username="root",
    )
    run_wizard(answers, env_path=paths.env_path, paths=paths, run_preflight=False)
    env = paths.env_path.read_text("utf-8")
    # Both lines render as commented placeholders (the existing
    # render_env pattern for unset optional values); neither is
    # active.
    assert "\nANGLERFISH_HONEYTOKENS__ENABLED=" not in env
    assert "\nANGLERFISH_HONEYTOKENS__CALLBACK_BASE_URL=" not in env
    assert "# ANGLERFISH_HONEYTOKENS__ENABLED=" in env
    assert "# ANGLERFISH_HONEYTOKENS__CALLBACK_BASE_URL=" in env
