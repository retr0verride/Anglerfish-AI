"""Tests for the wizard's rendering helpers."""

from __future__ import annotations

import base64
import ipaddress

import pytest
from pydantic import HttpUrl

from anglerfish.wizard.answers import WizardAnswers
from anglerfish.wizard.render import render_cowrie_cfg, render_env, render_nftables


def _answers(**overrides: object) -> WizardAnswers:
    base: dict[str, object] = {
        "terms_acknowledged": True,
        "bait_interface": "eth0",
        "service_interface": "eth1",
        "ollama_endpoint": HttpUrl("http://127.0.0.1:11434/"),
        "ollama_model": "qwen3:14b",
        "splunk_enabled": False,
        "fake_hostname": "srv-prod-01",
        "fake_username": "root",
    }
    base.update(overrides)
    return WizardAnswers(**base)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# render_env
# ---------------------------------------------------------------------------


def test_render_env_minimal_loopback() -> None:
    out = render_env(
        _answers(),
        session_secret="a" * 43,
        encryption_key=base64.b64encode(b"\x01" * 32).decode("ascii"),
        bridge_secret="b" * 43,
    )
    assert "ANGLERFISH_OLLAMA__BASE_URL=http://127.0.0.1:11434/" in out
    assert "ANGLERFISH_SPLUNK__ENABLED=false" in out
    assert "ANGLERFISH_DASHBOARD__SESSION_SECRET=" in out
    assert "ANGLERFISH_BRIDGE__SHARED_SECRET=" + ("b" * 43) in out
    assert "ANGLERFISH_BRIDGE_URL=http://127.0.0.1:8421" in out


def test_render_env_includes_trusted_remote() -> None:
    out = render_env(
        _answers(
            ollama_endpoint=HttpUrl("http://10.0.0.5:11434/"),
            ollama_trusted_remote_host=ipaddress.ip_address("10.0.0.5"),
        ),
        session_secret="x",
        encryption_key="y",
        bridge_secret="z",
    )
    assert "ANGLERFISH_OLLAMA__TRUSTED_REMOTE_HOST=10.0.0.5" in out


def test_render_env_omits_unset_optional_values() -> None:
    out = render_env(_answers(), session_secret="x", encryption_key="y", bridge_secret="z")
    lines = out.splitlines()
    # Unset optional values appear as a `# KEY=` comment line.
    assert "# ANGLERFISH_OLLAMA__TRUSTED_REMOTE_HOST=" in lines
    # No active assignment for the same key should appear.
    assert "ANGLERFISH_OLLAMA__TRUSTED_REMOTE_HOST=" not in lines


def test_render_env_splunk_enabled_emits_token() -> None:
    out = render_env(
        _answers(
            splunk_enabled=True,
            splunk_hec_url=HttpUrl("https://splunk.test:8088/services/collector/event"),
            splunk_hec_token="topsecrettoken",
        ),
        session_secret="x",
        encryption_key="y",
        bridge_secret="z",
    )
    assert "ANGLERFISH_SPLUNK__ENABLED=true" in out
    assert "ANGLERFISH_SPLUNK__HEC_URL=https://splunk.test:8088" in out
    assert "ANGLERFISH_SPLUNK__HEC_TOKEN=topsecrettoken" in out


def test_render_env_includes_threat_webhook_when_set() -> None:
    out = render_env(
        _answers(threat_alert_webhook=HttpUrl("https://hooks.test/x")),
        session_secret="x",
        encryption_key="y",
        bridge_secret="z",
    )
    assert "ANGLERFISH_THREAT__ALERT_WEBHOOK_URL=https://hooks.test/x" in out


# ---------------------------------------------------------------------------
# render_nftables
# ---------------------------------------------------------------------------


def test_render_nftables_uses_interface_names() -> None:
    out = render_nftables(_answers(bait_interface="ens1", service_interface="ens2"))
    assert 'iifname "ens1" tcp dport { 2222, 2223 }' in out
    assert 'oifname "ens2" tcp dport 11434' in out
    assert "policy drop" in out
    assert "table inet anglerfish" in out


def test_render_nftables_rejects_quote_injection() -> None:
    with pytest.raises(ValueError):
        render_nftables(_answers(bait_interface='evil" }'))


def test_render_nftables_rejects_overlong_iface_name() -> None:
    with pytest.raises(ValueError):
        render_nftables(_answers(service_interface="x" * 64))


def test_render_nftables_dashboard_port_override() -> None:
    out = render_nftables(_answers(), dashboard_port=8442)
    assert "tcp dport 8442 accept" in out


# ---------------------------------------------------------------------------
# render_cowrie_cfg
# ---------------------------------------------------------------------------


def test_render_cowrie_cfg_includes_anglerfish_plugin() -> None:
    out = render_cowrie_cfg(_answers())
    assert "[output_anglerfish]" in out
    assert "[honeypot]" in out
    assert "hostname = srv-prod-01" in out
    assert "listen_endpoints = tcp:2222:interface=0.0.0.0" in out


def test_render_cowrie_cfg_port_overrides() -> None:
    out = render_cowrie_cfg(_answers(), ssh_listen_port=2223, telnet_listen_port=2224)
    assert "listen_endpoints = tcp:2223:interface=0.0.0.0" in out
    assert "listen_endpoints = tcp:2224:interface=0.0.0.0" in out


# ---------------------------------------------------------------------------
# Stage 2C: lure env-file rendering + nftables port wiring
# ---------------------------------------------------------------------------


def test_render_env_includes_lure_section() -> None:
    out = render_env(_answers(), session_secret="x", encryption_key="y", bridge_secret="z")
    assert "ANGLERFISH_LURE__ENABLED=true" in out
    assert "ANGLERFISH_LURE__LISTEN_PORT=2222" in out
    assert "ANGLERFISH_LURE__HOSTNAME=srv-prod-01" in out
    assert "ANGLERFISH_LURE__HOST_KEY_DIR=/var/lib/anglerfish/lure-keys" in out


def test_render_env_lure_listen_host_empty_for_dhcp() -> None:
    # Default _answers() has dhcp=True bait_network; LISTEN_HOST must
    # be the commented-out form so the lure refuses to start until the
    # operator fills in the leased IP.
    out = render_env(_answers(), session_secret="x", encryption_key="y", bridge_secret="z")
    assert "# ANGLERFISH_LURE__LISTEN_HOST=" in out


def test_render_env_lure_listen_host_pulled_from_static_bait() -> None:
    from anglerfish.wizard.answers import NetworkConfig

    static_bait = NetworkConfig(
        dhcp=False,
        address="192.0.2.10/24",
        gateway=ipaddress.ip_address("192.0.2.1"),
        dns=(ipaddress.ip_address("1.1.1.1"),),
    )
    out = render_env(
        _answers(bait_network=static_bait),
        session_secret="x",
        encryption_key="y",
        bridge_secret="z",
    )
    assert "ANGLERFISH_LURE__LISTEN_HOST=192.0.2.10" in out


def test_render_nftables_default_lure_port_shares_cowrie_rule() -> None:
    """Default lure port (2222) coincides with Cowrie's SSH; one rule covers both."""
    out = render_nftables(_answers())
    # Cowrie SSH+telnet rule still emitted once.
    assert out.count("tcp dport { 2222, 2223 }") == 1
    # No separate per-lure-port rule when ports collide.
    assert "native lure" not in out


def test_render_nftables_distinct_lure_port_gets_separate_rule() -> None:
    out = render_nftables(_answers(), lure_listen_port=22)
    assert "tcp dport 22 accept" in out
    assert "native lure" in out
    assert "Cowrie (deprecation window)" in out
    # Cowrie rule still emitted for the transition window.
    assert "tcp dport { 2222, 2223 }" in out
