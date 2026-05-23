"""Wizard orchestrator.

:func:`run_wizard` is the runtime entry point. Given a
:class:`WizardAnswers` and a base path it produces every artefact a
working Anglerfish honeypot needs:

* ``<base>/anglerfish.env`` — env file consumed by every systemd unit.
* ``<base>/nftables/anglerfish.nft`` — firewall ruleset.
* ``<base>/cowrie.cfg`` — Cowrie main config.
* ``<systemd>/10-bait.network`` — bait NIC config (DHCP or static).
* ``<systemd>/20-service.network`` — service NIC config.
* ``/etc/hostname`` + ``/etc/hosts`` — VM hostname.
* ``<ops_home>/.ssh/authorized_keys`` — optional, if a key was supplied.
* ``<base>/wizard.json`` — operator answers, for ``--reconfigure``.

Tests call :func:`run_wizard` directly with a constructed
:class:`WizardAnswers`. The Typer CLI in :mod:`anglerfish.wizard.__main__`
wraps :func:`prompt_for_answers` around it for interactive use.
"""

from __future__ import annotations

import contextlib
import ipaddress
import logging
import os
import sys
from collections.abc import Callable
from pathlib import Path

from pydantic import HttpUrl, ValidationError

from anglerfish.audit import AuditLog
from anglerfish.wizard.answers import NetworkConfig, WizardAnswers, WizardOutput
from anglerfish.wizard.network import list_interfaces
from anglerfish.wizard.persistence import save_answers
from anglerfish.wizard.preflight import PreflightChecker
from anglerfish.wizard.render import (
    render_authorized_keys,
    render_cowrie_cfg,
    render_env,
    render_hostname_files,
    render_nftables,
    render_systemd_network,
)
from anglerfish.wizard.secrets import (
    generate_bridge_secret,
    generate_encryption_key,
    generate_session_secret,
)
from anglerfish.wizard.terms import TERMS

__all__ = [
    "TermsDeclinedError",
    "WizardPaths",
    "prompt_for_answers",
    "run_wizard",
]


_logger = logging.getLogger(__name__)


class TermsDeclinedError(RuntimeError):
    """Raised when the operator declines the responsible-use terms."""


class WizardPaths:
    """Resolves output file locations off a single base directory.

    The defaults match the production layout under ``/etc/anglerfish/``
    plus the standard system locations for ``systemd-networkd`` and
    ``/etc/hostname``. Tests pass a ``tmp_path``-derived base instead.
    """

    def __init__(
        self,
        env_path: Path,
        *,
        nftables_path: Path | None = None,
        cowrie_cfg_path: Path | None = None,
        bait_network_path: Path | None = None,
        service_network_path: Path | None = None,
        hostname_path: Path | None = None,
        hosts_path: Path | None = None,
        ops_home: Path | None = None,
        answers_path: Path | None = None,
        systemd_network_dir: Path | None = None,
    ) -> None:
        base = env_path.parent
        self.env_path = env_path
        self.nftables_path = (
            nftables_path if nftables_path is not None else base / "nftables" / "anglerfish.nft"
        )
        self.cowrie_cfg_path = (
            cowrie_cfg_path if cowrie_cfg_path is not None else base / "cowrie.cfg"
        )
        self.answers_path = answers_path if answers_path is not None else base / "wizard.json"
        # System paths default to real OS locations; tests override.
        systemd_root = (
            systemd_network_dir if systemd_network_dir is not None else Path("/etc/systemd/network")
        )
        self.bait_network_path = (
            bait_network_path if bait_network_path is not None else systemd_root / "10-bait.network"
        )
        self.service_network_path = (
            service_network_path
            if service_network_path is not None
            else systemd_root / "20-service.network"
        )
        self.hostname_path = hostname_path if hostname_path is not None else Path("/etc/hostname")
        self.hosts_path = hosts_path if hosts_path is not None else Path("/etc/hosts")
        self.ops_home = ops_home if ops_home is not None else Path("/home/anglerfish-ops")


def run_wizard(
    answers: WizardAnswers,
    *,
    env_path: Path,
    paths: WizardPaths | None = None,
    session_secret: str | None = None,
    encryption_key: str | None = None,
    bridge_secret: str | None = None,
    preflight: PreflightChecker | None = None,
    run_preflight: bool = True,
    audit: AuditLog | None = None,
) -> WizardOutput:
    """Generate secrets, render artefacts, write them atomically.

    The ``paths`` argument resolves every output path. When omitted, a
    default :class:`WizardPaths` is built off ``env_path``. ``preflight``
    defaults to a :class:`PreflightChecker` with the standard 5 s
    timeout; set ``run_preflight=False`` to skip reachability checks
    entirely (useful in tests).
    """
    if not answers.terms_acknowledged:
        raise TermsDeclinedError(
            "The responsible-use terms were not acknowledged. Aborting.",
        )

    resolved = paths if paths is not None else WizardPaths(env_path)

    preflight_results: list[str] = []
    if run_preflight:
        checker = preflight if preflight is not None else PreflightChecker()
        results = checker.run(
            ollama_url=str(answers.ollama_endpoint),
            splunk_hec_url=(
                str(answers.splunk_hec_url)
                if answers.splunk_enabled and answers.splunk_hec_url is not None
                else None
            ),
            webhook_url=(
                str(answers.threat_alert_webhook)
                if answers.threat_alert_webhook is not None
                else None
            ),
        )
        preflight_results = [r.render() for r in results]

    secret_was_generated = session_secret is None
    key_was_generated = encryption_key is None
    bridge_was_generated = bridge_secret is None
    secret = session_secret if session_secret is not None else generate_session_secret()
    key = encryption_key if encryption_key is not None else generate_encryption_key()
    bridge_tok = bridge_secret if bridge_secret is not None else generate_bridge_secret()

    env_content = render_env(
        answers,
        session_secret=secret,
        encryption_key=key,
        bridge_secret=bridge_tok,
    )
    nft_content = render_nftables(answers)
    cowrie_content = render_cowrie_cfg(answers)
    bait_net = render_systemd_network(answers.bait_interface, answers.bait_network)
    service_net = render_systemd_network(answers.service_interface, answers.service_network)
    etc_hostname, etc_hosts = render_hostname_files(answers.vm_hostname)

    _atomic_write(resolved.env_path, env_content, mode=0o600)
    _atomic_write(resolved.nftables_path, nft_content, mode=0o640)
    _atomic_write(resolved.cowrie_cfg_path, cowrie_content, mode=0o640)
    _atomic_write(resolved.bait_network_path, bait_net, mode=0o644)
    _atomic_write(resolved.service_network_path, service_net, mode=0o644)
    _atomic_write(resolved.hostname_path, etc_hostname, mode=0o644)
    _atomic_write(resolved.hosts_path, etc_hosts, mode=0o644)

    authorized_keys_path: Path | None = None
    if answers.operator_ssh_pubkey is not None:
        ak_body = render_authorized_keys(answers.operator_ssh_pubkey)
        authorized_keys_path = resolved.ops_home / ".ssh" / "authorized_keys"
        _atomic_write(authorized_keys_path, ak_body, mode=0o600)

    save_answers(answers, resolved.answers_path)

    if audit is not None:
        audit.record(
            "wizard.run",
            env_path=str(resolved.env_path),
            bait_interface=answers.bait_interface,
            service_interface=answers.service_interface,
            secrets_regenerated={
                "dashboard_session_secret": secret_was_generated,
                "credentials_encryption_key": key_was_generated,
                "bridge_shared_secret": bridge_was_generated,
            },
            preflight=preflight_results,
        )

    return WizardOutput(
        env_path=resolved.env_path,
        nftables_path=resolved.nftables_path,
        cowrie_cfg_path=resolved.cowrie_cfg_path,
        bait_network_path=resolved.bait_network_path,
        service_network_path=resolved.service_network_path,
        hostname_path=resolved.hostname_path,
        answers_path=resolved.answers_path,
        authorized_keys_path=authorized_keys_path,
        dashboard_session_secret_generated=secret_was_generated,
        credentials_encryption_key_generated=key_was_generated,
        bridge_shared_secret_generated=bridge_was_generated,
        bait_interface=answers.bait_interface,
        service_interface=answers.service_interface,
        preflight_results=tuple(preflight_results),
    )


def _atomic_write(path: Path, content: str, *, mode: int) -> None:
    """Write ``content`` to ``path`` atomically with the requested mode."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_suffix(path.suffix + ".tmp")
    tmp_path.write_text(content, encoding="utf-8")
    # Windows: chmod is a partial no-op; suppress without warning.
    with contextlib.suppress(OSError):
        os.chmod(tmp_path, mode)
    os.replace(tmp_path, path)


# ---------------------------------------------------------------------------
# Interactive prompting — runs against any callable I/O pair so tests can
# inject a scripted prompter without touching stdin.
# ---------------------------------------------------------------------------


PromptFn = Callable[[str, str | None], str]
"""``(label, default) -> str`` — returns the operator's answer."""

ConfirmFn = Callable[[str, bool], bool]
"""``(label, default) -> bool`` — returns the operator's yes/no choice."""


def _default_output(text: str) -> None:
    sys.stdout.write(text)


def prompt_for_answers(
    *,
    prompt: PromptFn,
    confirm: ConfirmFn,
    available_interfaces: list[str] | None = None,
    output: Callable[[str], None] = _default_output,
    defaults: WizardAnswers | None = None,
) -> WizardAnswers:
    """Build a :class:`WizardAnswers` by prompting the operator.

    ``defaults`` is consulted for default values in every prompt — this
    is the path that ``--reconfigure`` takes when a previous answers
    file exists.
    """
    output(TERMS + "\n")
    accepted = confirm("I have read and agree to the terms above", False)
    if not accepted:
        raise TermsDeclinedError("Terms declined — aborting wizard.")

    interfaces = list_interfaces() if available_interfaces is None else list(available_interfaces)
    suggestion_bait = (
        defaults.bait_interface
        if defaults is not None
        else (interfaces[0] if interfaces else "eth0")
    )
    suggestion_service = (
        defaults.service_interface
        if defaults is not None
        else (interfaces[1] if len(interfaces) > 1 else "eth1")
    )
    output(
        "\nDetected interfaces: "
        + (", ".join(interfaces) if interfaces else "(none — type names manually)")
        + "\n",
    )

    vm_hostname = prompt(
        "VM hostname (operating system, not the fake shell hostname)",
        defaults.vm_hostname if defaults is not None else "anglerfish-honeypot",
    ).strip()

    bait = prompt("Bait interface (exposed to attackers)", suggestion_bait).strip()
    service = prompt(
        "Service interface (Ollama, Splunk, dashboard)",
        suggestion_service,
    ).strip()

    bait_network = _prompt_network(
        prompt,
        confirm,
        label=f"bait NIC ({bait})",
        default=defaults.bait_network if defaults is not None else None,
    )
    service_network = _prompt_network(
        prompt,
        confirm,
        label=f"service NIC ({service})",
        default=defaults.service_network if defaults is not None else None,
    )

    operator_username = prompt(
        "Operator UNIX username (separate from honeypot service users)",
        defaults.operator_username if defaults is not None else "anglerfish-ops",
    ).strip()
    ssh_default = (
        defaults.operator_ssh_pubkey
        if defaults is not None and defaults.operator_ssh_pubkey
        else ""
    )
    operator_pubkey_raw = prompt(
        "Operator SSH public key line (paste or blank to skip)",
        ssh_default,
    ).strip()
    operator_ssh_pubkey: str | None = operator_pubkey_raw or None

    # Dashboard admin authentication.
    dashboard_admin_username = prompt(
        "Dashboard admin username",
        defaults.dashboard_admin_username if defaults is not None else "admin",
    ).strip()
    # Re-prompt the password each run — never read the previous one back
    # in plaintext; the operator either supplies a new one or accepts the
    # saved hash by leaving the prompt blank.
    keep_existing_hash = defaults is not None and defaults.dashboard_admin_password_hash is not None
    if keep_existing_hash:
        password_prompt_label = (
            "Dashboard admin password (blank to keep the previously-configured one)"  # nosec B105
        )
    else:
        password_prompt_label = (
            "Dashboard admin password (blank for open-mode — only safe on an isolated NIC)"  # nosec B105
        )
    plain_password = prompt(password_prompt_label, "").strip()
    dashboard_admin_password_hash: str | None
    if plain_password:
        from anglerfish.dashboard.auth import hash_password

        dashboard_admin_password_hash = hash_password(plain_password)
    elif keep_existing_hash:
        # We *only* reach this branch when defaults is not None and its
        # dashboard_admin_password_hash is not None — the keep_existing_hash
        # guard above guarantees both.
        dashboard_admin_password_hash = (
            defaults.dashboard_admin_password_hash  # type: ignore[union-attr]
        )
    else:
        dashboard_admin_password_hash = None

    ollama_endpoint_default = (
        str(defaults.ollama_endpoint) if defaults is not None else "http://127.0.0.1:11434/"
    )
    ollama_endpoint_str = prompt("Ollama endpoint URL", ollama_endpoint_default).strip()
    ollama_trusted: ipaddress.IPv4Address | ipaddress.IPv6Address | None = None
    try:
        ollama_endpoint = HttpUrl(ollama_endpoint_str)
    except ValidationError as exc:
        raise ValueError(f"invalid Ollama endpoint URL: {ollama_endpoint_str!r}") from exc

    host = ollama_endpoint.host
    if host is not None and host not in {"127.0.0.1", "::1", "localhost"}:
        trusted_default = (
            str(defaults.ollama_trusted_remote_host)
            if defaults is not None and defaults.ollama_trusted_remote_host is not None
            else host or ""
        )
        trusted_str = prompt(
            "Trusted remote Ollama IP (must match endpoint host)",
            trusted_default,
        ).strip()
        try:
            ollama_trusted = ipaddress.ip_address(trusted_str)
        except ValueError as exc:
            raise ValueError(f"invalid trusted remote IP: {trusted_str!r}") from exc

    ollama_model = prompt(
        "Ollama model tag",
        defaults.ollama_model if defaults is not None else "deepseek-coder:6.7b",
    ).strip()

    fake_hostname = prompt(
        "Fake hostname for the AI shell",
        defaults.fake_hostname if defaults is not None else "srv-prod-01",
    ).strip()
    fake_username = prompt(
        "Fake username for the AI shell",
        defaults.fake_username if defaults is not None else "root",
    ).strip()

    splunk_default = defaults.splunk_enabled if defaults is not None else False
    splunk_enabled = confirm("Enable Splunk HEC forwarding?", splunk_default)
    splunk_url: HttpUrl | None = None
    splunk_token: str | None = None
    if splunk_enabled:
        hec_default = (
            str(defaults.splunk_hec_url)
            if defaults is not None and defaults.splunk_hec_url is not None
            else "https://splunk.internal:8088/services/collector/event"
        )
        url_str = prompt("Splunk HEC URL", hec_default).strip()
        try:
            splunk_url = HttpUrl(url_str)
        except ValidationError as exc:
            raise ValueError(f"invalid Splunk HEC URL: {url_str!r}") from exc
        token_default = (
            defaults.splunk_hec_token
            if defaults is not None and defaults.splunk_hec_token is not None
            else None
        )
        splunk_token = prompt("Splunk HEC token", token_default).strip() or None

    webhook_default = (
        str(defaults.threat_alert_webhook)
        if defaults is not None and defaults.threat_alert_webhook is not None
        else ""
    )
    webhook_str = prompt(
        "Threat alert webhook URL (optional, blank to skip)",
        webhook_default,
    ).strip()
    webhook: HttpUrl | None = None
    if webhook_str:
        try:
            webhook = HttpUrl(webhook_str)
        except ValidationError as exc:
            raise ValueError(f"invalid webhook URL: {webhook_str!r}") from exc

    maxmind_default = (
        defaults.maxmind_license_key
        if defaults is not None and defaults.maxmind_license_key is not None
        else ""
    )
    maxmind_key_raw = prompt(
        "MaxMind GeoLite2 licence key (optional, blank to skip)",
        maxmind_default,
    ).strip()
    maxmind_license_key: str | None = maxmind_key_raw or None

    return WizardAnswers(
        terms_acknowledged=True,
        vm_hostname=vm_hostname,
        bait_interface=bait,
        service_interface=service,
        bait_network=bait_network,
        service_network=service_network,
        operator_username=operator_username,
        operator_ssh_pubkey=operator_ssh_pubkey,
        dashboard_admin_username=dashboard_admin_username,
        dashboard_admin_password_hash=dashboard_admin_password_hash,
        ollama_endpoint=ollama_endpoint,
        ollama_trusted_remote_host=ollama_trusted,
        ollama_model=ollama_model,
        splunk_enabled=splunk_enabled,
        splunk_hec_url=splunk_url,
        splunk_hec_token=splunk_token,
        threat_alert_webhook=webhook,
        maxmind_license_key=maxmind_license_key,
        fake_hostname=fake_hostname,
        fake_username=fake_username,
    )


def _prompt_network(
    prompt: PromptFn,
    confirm: ConfirmFn,
    *,
    label: str,
    default: NetworkConfig | None,
) -> NetworkConfig:
    """Prompt for one NIC's :class:`NetworkConfig` (DHCP or static)."""
    dhcp_default = default.dhcp if default is not None else True
    if confirm(f"DHCP on the {label}?", dhcp_default):
        return NetworkConfig(dhcp=True)

    addr_default = default.address if default is not None and default.address is not None else ""
    address = prompt(
        f"{label}: static address in CIDR form (e.g. 10.0.0.5/24)",
        addr_default,
    ).strip()
    if not address:
        raise ValueError(f"{label}: address required for static config")

    gw_default = str(default.gateway) if default is not None and default.gateway is not None else ""
    gateway_str = prompt(f"{label}: gateway IP", gw_default).strip()
    if not gateway_str:
        raise ValueError(f"{label}: gateway required for static config")
    try:
        gateway = ipaddress.ip_address(gateway_str)
    except ValueError as exc:
        raise ValueError(f"{label}: invalid gateway {gateway_str!r}") from exc

    dns_default = (
        ", ".join(str(d) for d in default.dns) if default is not None and default.dns else "1.1.1.1"
    )
    dns_str = prompt(f"{label}: DNS servers (comma-separated)", dns_default).strip()
    dns_list: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
    if dns_str:
        for entry in (s.strip() for s in dns_str.split(",")):
            if not entry:
                continue
            try:
                dns_list.append(ipaddress.ip_address(entry))
            except ValueError as exc:
                raise ValueError(f"{label}: invalid DNS {entry!r}") from exc

    return NetworkConfig(
        dhcp=False,
        address=address,
        gateway=gateway,
        dns=tuple(dns_list),
    )
