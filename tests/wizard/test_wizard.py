"""Tests for the wizard orchestrator and the interactive prompter."""

from __future__ import annotations

import base64
import sys
from collections.abc import Callable, Iterator
from pathlib import Path

import pytest
from pydantic import HttpUrl

from anglerfish.wizard import (
    NetworkConfig,
    TermsDeclinedError,
    WizardAnswers,
    WizardPaths,
    prompt_for_answers,
    run_wizard,
)

_ED25519_BLOB = base64.b64encode(b"\x00\x00\x00\x0bssh-ed25519" + b"\x00" * 40).decode()


def _answers(**overrides: object) -> WizardAnswers:
    base: dict[str, object] = {
        "terms_acknowledged": True,
        "bait_interface": "eth0",
        "service_interface": "eth1",
        "ollama_endpoint": HttpUrl("http://127.0.0.1:11434/"),
        "ollama_model": "qwen3:14b",
        "fake_hostname": "srv-prod-01",
        "fake_username": "root",
    }
    base.update(overrides)
    return WizardAnswers(**base)  # type: ignore[arg-type]


def _paths(tmp_path: Path) -> WizardPaths:
    """A WizardPaths rooted entirely in ``tmp_path`` — never touches the OS."""
    return WizardPaths(
        env_path=tmp_path / "anglerfish.env",
        bait_network_path=tmp_path / "systemd" / "10-bait.network",
        service_network_path=tmp_path / "systemd" / "20-service.network",
        hostname_path=tmp_path / "etc-hostname",
        hosts_path=tmp_path / "etc-hosts",
        ops_home=tmp_path / "ops-home",
    )


# ---------------------------------------------------------------------------
# run_wizard
# ---------------------------------------------------------------------------


def test_run_wizard_writes_every_artefact(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    output = run_wizard(_answers(), env_path=paths.env_path, paths=paths, run_preflight=False)

    assert output.env_path.exists()
    assert output.nftables_path.exists()
    assert output.bait_network_path.exists()
    assert output.service_network_path.exists()
    assert output.hostname_path.exists()
    assert output.answers_path.exists()
    assert output.authorized_keys_path is None  # no SSH key provided

    env_content = output.env_path.read_text("utf-8")
    assert "ANGLERFISH_DASHBOARD__SESSION_SECRET=" in env_content
    assert "ANGLERFISH_CREDENTIALS__ENCRYPTION_KEY=" in env_content
    assert "ANGLERFISH_BRIDGE__SHARED_SECRET=" in env_content

    assert "DHCP=yes" in output.bait_network_path.read_text("utf-8")
    assert "DHCP=yes" in output.service_network_path.read_text("utf-8")
    assert output.hostname_path.read_text("utf-8").startswith("anglerfish-honeypot")


def test_run_wizard_writes_authorized_keys_when_pubkey_provided(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    answers = _answers(operator_ssh_pubkey=f"ssh-ed25519 {_ED25519_BLOB} ops")
    output = run_wizard(answers, env_path=paths.env_path, paths=paths, run_preflight=False)
    assert output.authorized_keys_path is not None
    assert output.authorized_keys_path.exists()
    body = output.authorized_keys_path.read_text("utf-8")
    assert body.startswith("ssh-ed25519 ")
    assert body.endswith("\n")


def test_run_wizard_rejects_invalid_ssh_key(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    answers = _answers(operator_ssh_pubkey="ssh-dss invalid-key")
    with pytest.raises(ValueError):
        run_wizard(answers, env_path=paths.env_path, paths=paths, run_preflight=False)


def test_run_wizard_uses_supplied_secrets(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    output = run_wizard(
        _answers(),
        env_path=paths.env_path,
        paths=paths,
        session_secret="x" * 43,
        encryption_key="y",
        bridge_secret="z" * 43,
        run_preflight=False,
    )
    assert output.dashboard_session_secret_generated is False
    assert output.credentials_encryption_key_generated is False
    assert output.bridge_shared_secret_generated is False
    content = output.env_path.read_text("utf-8")
    assert "ANGLERFISH_DASHBOARD__SESSION_SECRET=" + ("x" * 43) in content
    assert "ANGLERFISH_BRIDGE__SHARED_SECRET=" + ("z" * 43) in content


def test_run_wizard_refuses_without_acknowledgement(tmp_path: Path) -> None:
    with pytest.raises(TermsDeclinedError):
        run_wizard(
            _answers(terms_acknowledged=False),
            env_path=tmp_path / "x.env",
            paths=_paths(tmp_path),
            run_preflight=False,
        )


def test_run_wizard_explicit_artefact_paths(tmp_path: Path) -> None:
    paths = WizardPaths(
        env_path=tmp_path / "anglerfish.env",
        nftables_path=tmp_path / "custom" / "anglerfish.nft",
        bait_network_path=tmp_path / "systemd" / "10-bait.network",
        service_network_path=tmp_path / "systemd" / "20-service.network",
        hostname_path=tmp_path / "etc-hostname",
        hosts_path=tmp_path / "etc-hosts",
        ops_home=tmp_path / "ops-home",
    )
    output = run_wizard(
        _answers(),
        env_path=paths.env_path,
        paths=paths,
        run_preflight=False,
    )
    assert output.nftables_path == paths.nftables_path
    assert paths.nftables_path.exists()


def test_run_wizard_persists_answers(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    output = run_wizard(_answers(), env_path=paths.env_path, paths=paths, run_preflight=False)
    assert output.answers_path.exists()
    # answers.json must NOT contain the dashboard secret value
    body = output.answers_path.read_text("utf-8")
    env_body = output.env_path.read_text("utf-8")
    for line in env_body.splitlines():
        if not line.startswith("ANGLERFISH_DASHBOARD__SESSION_SECRET="):
            continue
        secret_value = line.split("=", 1)[1]
        assert secret_value not in body


def test_run_wizard_static_network_renders(tmp_path: Path) -> None:
    import ipaddress

    paths = _paths(tmp_path)
    answers = _answers(
        bait_network=NetworkConfig(
            dhcp=False,
            address="192.0.2.5/24",
            gateway=ipaddress.ip_address("192.0.2.1"),
            dns=(ipaddress.ip_address("1.1.1.1"),),
        ),
    )
    output = run_wizard(answers, env_path=paths.env_path, paths=paths, run_preflight=False)
    body = output.bait_network_path.read_text("utf-8")
    assert "Address=192.0.2.5/24" in body
    assert "Gateway=192.0.2.1" in body
    assert "DNS=1.1.1.1" in body


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permission semantics")
def test_run_wizard_writes_env_with_0600(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    run_wizard(_answers(), env_path=paths.env_path, paths=paths, run_preflight=False)
    mode = paths.env_path.stat().st_mode & 0o777
    assert mode == 0o600


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permission semantics")
def test_run_wizard_writes_nftables_with_0640(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    output = run_wizard(_answers(), env_path=paths.env_path, paths=paths, run_preflight=False)
    mode = output.nftables_path.stat().st_mode & 0o777
    assert mode == 0o640


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permission semantics")
def test_run_wizard_writes_authorized_keys_with_0600(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    answers = _answers(operator_ssh_pubkey=f"ssh-ed25519 {_ED25519_BLOB}")
    output = run_wizard(answers, env_path=paths.env_path, paths=paths, run_preflight=False)
    assert output.authorized_keys_path is not None
    mode = output.authorized_keys_path.stat().st_mode & 0o777
    assert mode == 0o600


def test_run_wizard_preflight_invoked_when_enabled(tmp_path: Path) -> None:
    from anglerfish.wizard.preflight import CheckResult, PreflightChecker

    class _StubChecker(PreflightChecker):
        def run(  # type: ignore[no-untyped-def]
            self,
            *,
            _ollama_url=None,
            _splunk_hec_url=None,
            _webhook_url=None,
            **_kwargs,
        ):
            return [CheckResult(service="ollama", success=True, detail="version test")]

    paths = _paths(tmp_path)
    output = run_wizard(
        _answers(),
        env_path=paths.env_path,
        paths=paths,
        preflight=_StubChecker(),
        run_preflight=True,
    )
    assert len(output.preflight_results) == 1
    assert "ollama" in output.preflight_results[0]


# ---------------------------------------------------------------------------
# prompt_for_answers
# ---------------------------------------------------------------------------


def _make_prompter(
    *,
    confirms: list[bool],
    prompts: list[str],
) -> tuple[Callable[[str, str | None], str], Callable[[str, bool], bool]]:
    c_iter: Iterator[bool] = iter(confirms)
    p_iter: Iterator[str] = iter(prompts)

    def _prompt(label: str, default: str | None) -> str:
        return next(p_iter)

    def _confirm(label: str, default: bool) -> bool:
        return next(c_iter)

    return _prompt, _confirm


def test_prompt_for_answers_happy_path_dhcp() -> None:
    # confirms: terms, bait DHCP, service DHCP, honeytokens-decline.
    confirms = [True, True, True, False, False]  # +counter-deception decline (Stage 12)
    prompts = [
        "anglerfish-vm",  # vm_hostname
        "eth0",  # bait_interface
        "eth1",  # service_interface
        "anglerfish-ops",  # operator_username
        "",  # operator_ssh_pubkey
        "admin",  # dashboard_admin_username
        "",  # dashboard_admin_password (blank → open mode)
        "http://127.0.0.1:11434/",  # ollama_endpoint
        "qwen3:14b",  # ollama_model
        "srv-prod-01",  # fake_hostname
        "root",  # fake_username
        "",  # webhook
        "",  # maxmind_license_key
    ]
    _prompt, _confirm = _make_prompter(confirms=confirms, prompts=prompts)
    answers = prompt_for_answers(
        prompt=_prompt,
        confirm=_confirm,
        available_interfaces=["eth0", "eth1"],
        output=lambda _s: None,
    )
    assert answers.vm_hostname == "anglerfish-vm"
    assert answers.bait_network.dhcp is True
    assert answers.service_network.dhcp is True
    assert answers.operator_ssh_pubkey is None


def test_prompt_for_answers_static_network() -> None:
    # confirms: terms, bait DHCP=False, service DHCP=True, honeytokens-decline.
    confirms = [True, False, True, False, False]  # +counter-deception decline (Stage 12)
    prompts = [
        "anglerfish-vm",
        "eth0",
        "eth1",
        "10.0.0.5/24",
        "10.0.0.1",
        "1.1.1.1,9.9.9.9",
        "anglerfish-ops",
        "",
        "admin",  # dashboard admin user
        "",  # dashboard password (open mode)
        "http://127.0.0.1:11434/",
        "qwen3:14b",
        "srv-prod-01",
        "root",
        "",
        "",  # maxmind_license_key
    ]
    _prompt, _confirm = _make_prompter(confirms=confirms, prompts=prompts)
    answers = prompt_for_answers(
        prompt=_prompt,
        confirm=_confirm,
        available_interfaces=["eth0", "eth1"],
        output=lambda _s: None,
    )
    assert answers.bait_network.dhcp is False
    assert answers.bait_network.address == "10.0.0.5/24"
    assert str(answers.bait_network.gateway) == "10.0.0.1"
    assert len(answers.bait_network.dns) == 2


def test_prompt_for_answers_uses_defaults() -> None:
    defaults = _answers(
        bait_interface="ens1",
        service_interface="ens2",
        vm_hostname="prior-host",
    )
    seen_defaults: list[str | None] = []

    def _prompt(label: str, default: str | None) -> str:
        seen_defaults.append(default)
        return default or ""

    def _confirm(label: str, default: bool) -> bool:
        # Always accept terms; honour the prompt default for everything else.
        if "terms" in label.lower():
            return True
        return default

    prompt_for_answers(
        prompt=_prompt,
        confirm=_confirm,
        available_interfaces=[],
        output=lambda _s: None,
        defaults=defaults,
    )
    assert "prior-host" in seen_defaults
    assert "ens1" in seen_defaults
    assert "ens2" in seen_defaults


def test_prompt_for_answers_decline_terms_raises() -> None:
    confirms = [False]

    def _prompt(label: str, default: str | None) -> str:
        raise AssertionError("should not prompt after decline")

    def _confirm(label: str, default: bool) -> bool:
        return confirms.pop(0)

    with pytest.raises(TermsDeclinedError):
        prompt_for_answers(prompt=_prompt, confirm=_confirm, output=lambda _s: None)


def test_prompt_for_answers_invalid_ollama_url_raises() -> None:
    confirms = [True, True, True]
    prompts = [
        "anglerfish-vm",
        "eth0",
        "eth1",
        "anglerfish-ops",
        "",
        "admin",
        "",
        "not a url",
    ]
    _prompt, _confirm = _make_prompter(confirms=confirms, prompts=prompts)
    with pytest.raises(ValueError, match="invalid Ollama"):
        prompt_for_answers(
            prompt=_prompt,
            confirm=_confirm,
            available_interfaces=[],
            output=lambda _s: None,
        )


def test_prompt_for_answers_static_missing_address_raises() -> None:
    confirms = [True, False]
    prompts = ["anglerfish-vm", "eth0", "eth1", ""]
    _prompt, _confirm = _make_prompter(confirms=confirms, prompts=prompts)
    with pytest.raises(ValueError, match="address required"):
        prompt_for_answers(
            prompt=_prompt,
            confirm=_confirm,
            available_interfaces=[],
            output=lambda _s: None,
        )


def test_prompt_for_answers_static_missing_gateway_raises() -> None:
    confirms = [True, False]
    prompts = ["anglerfish-vm", "eth0", "eth1", "10.0.0.5/24", ""]
    _prompt, _confirm = _make_prompter(confirms=confirms, prompts=prompts)
    with pytest.raises(ValueError, match="gateway required"):
        prompt_for_answers(
            prompt=_prompt,
            confirm=_confirm,
            available_interfaces=[],
            output=lambda _s: None,
        )


def test_prompt_for_answers_static_invalid_gateway_raises() -> None:
    confirms = [True, False]
    prompts = ["anglerfish-vm", "eth0", "eth1", "10.0.0.5/24", "not-an-ip"]
    _prompt, _confirm = _make_prompter(confirms=confirms, prompts=prompts)
    with pytest.raises(ValueError, match="invalid gateway"):
        prompt_for_answers(
            prompt=_prompt,
            confirm=_confirm,
            available_interfaces=[],
            output=lambda _s: None,
        )


# The Splunk-enabled prompt test was removed in 2026-05 alongside
# the Cowrie / forwarder removal; Splunk is no longer asked about.


def test_prompt_for_answers_remote_ollama_with_trusted_host() -> None:
    # confirms: terms, bait DHCP, service DHCP, honeytokens-decline.
    confirms = [True, True, True, False, False]  # +counter-deception decline (Stage 12)
    prompts = [
        "anglerfish-vm",
        "eth0",
        "eth1",
        "anglerfish-ops",
        "",
        "admin",
        "",
        "http://10.0.0.5:11434/",
        "10.0.0.5",
        "qwen3:14b",
        "srv-prod-01",
        "root",
        "",
        "",  # maxmind_license_key
    ]
    _prompt, _confirm = _make_prompter(confirms=confirms, prompts=prompts)
    answers = prompt_for_answers(
        prompt=_prompt,
        confirm=_confirm,
        available_interfaces=[],
        output=lambda _s: None,
    )
    assert str(answers.ollama_trusted_remote_host) == "10.0.0.5"


def test_prompt_for_answers_invalid_webhook_raises() -> None:
    confirms = [True, True, True, False, False]  # +counter-deception decline (Stage 12)
    prompts = [
        "anglerfish-vm",
        "eth0",
        "eth1",
        "anglerfish-ops",
        "",
        "admin",
        "",
        "http://127.0.0.1:11434/",
        "qwen3:14b",
        "srv-prod-01",
        "root",
        "not a url",
    ]
    _prompt, _confirm = _make_prompter(confirms=confirms, prompts=prompts)
    with pytest.raises(ValueError, match="webhook"):
        prompt_for_answers(
            prompt=_prompt,
            confirm=_confirm,
            available_interfaces=[],
            output=lambda _s: None,
        )
