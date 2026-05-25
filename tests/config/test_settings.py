"""Tests for :mod:`anglerfish.config.settings`."""

from __future__ import annotations

import base64

import pytest
from pydantic import SecretStr, ValidationError

from anglerfish.config import AnglerfishSettings, load_settings
from anglerfish.config.models import (
    BridgeConfig,
    CredentialsConfig,
    DashboardConfig,
    DefenseConfig,
    LogLevel,
    OllamaConfig,
)


def test_settings_direct_construction(
    session_secret: str,
    encryption_key_b64: str,
) -> None:
    s = AnglerfishSettings(
        dashboard=DashboardConfig(session_secret=SecretStr(session_secret)),
        credentials=CredentialsConfig(encryption_key=SecretStr(encryption_key_b64)),
    )
    assert s.log_level == LogLevel.INFO
    assert s.ollama.base_url.host == "127.0.0.1"
    assert s.bridge.fake_hostname == "srv-prod-01"
    assert s.rate_limit.max_concurrent_requests == 8
    # DefenseConfig defaults are reachable via the settings root.
    assert s.defense.output_filter_enabled is True
    assert s.defense.injection_filter_enabled is True
    assert s.defense.injection_threshold == pytest.approx(0.7)
    assert s.defense.fast_model_expected_hash is None


def test_settings_missing_required_fields_fails() -> None:
    with pytest.raises(ValidationError):
        AnglerfishSettings()


def test_load_settings_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ANGLERFISH_DASHBOARD__SESSION_SECRET", "y" * 40)
    monkeypatch.setenv(
        "ANGLERFISH_CREDENTIALS__ENCRYPTION_KEY",
        base64.b64encode(b"\x02" * 32).decode("ascii"),
    )
    monkeypatch.setenv("ANGLERFISH_LOG_LEVEL", "DEBUG")
    monkeypatch.setenv("ANGLERFISH_BRIDGE__FAKE_HOSTNAME", "honeypot-7")

    s = load_settings()
    assert s.log_level == LogLevel.DEBUG
    assert s.bridge.fake_hostname == "honeypot-7"
    assert s.dashboard.session_secret.get_secret_value() == "y" * 40


def test_load_settings_caches_result(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ANGLERFISH_DASHBOARD__SESSION_SECRET", "z" * 32)
    monkeypatch.setenv(
        "ANGLERFISH_CREDENTIALS__ENCRYPTION_KEY",
        base64.b64encode(b"\x03" * 32).decode("ascii"),
    )
    first = load_settings()
    second = load_settings()
    assert first is second


def test_load_settings_propagates_validation_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ANGLERFISH_DASHBOARD__SESSION_SECRET", "tooshort")
    monkeypatch.setenv(
        "ANGLERFISH_CREDENTIALS__ENCRYPTION_KEY",
        base64.b64encode(b"\x04" * 32).decode("ascii"),
    )
    with pytest.raises(ValidationError):
        load_settings()


# ---------------------------------------------------------------------------
# Stage 1.8.5 cross-field validator: defense.scan_max_chars must be >=
# both ollama.max_response_chars and bridge.max_input_chars. An operator
# who raises the I/O caps must remember to raise the scan cap too, or
# defense silently shrinks to a prefix of long inputs.
# ---------------------------------------------------------------------------


def test_scan_cap_below_response_cap_is_rejected(
    session_secret: str,
    encryption_key_b64: str,
) -> None:
    with pytest.raises(ValidationError, match=r"scan_max_chars.*ollama\.max_response_chars"):
        AnglerfishSettings(
            dashboard=DashboardConfig(session_secret=SecretStr(session_secret)),
            credentials=CredentialsConfig(encryption_key=SecretStr(encryption_key_b64)),
            ollama=OllamaConfig(max_response_chars=16384),
            defense=DefenseConfig(scan_max_chars=8192),
        )


def test_scan_cap_below_input_cap_is_rejected(
    session_secret: str,
    encryption_key_b64: str,
) -> None:
    with pytest.raises(ValidationError, match=r"scan_max_chars.*bridge\.max_input_chars"):
        AnglerfishSettings(
            dashboard=DashboardConfig(session_secret=SecretStr(session_secret)),
            credentials=CredentialsConfig(encryption_key=SecretStr(encryption_key_b64)),
            bridge=BridgeConfig(max_input_chars=16384),
            defense=DefenseConfig(scan_max_chars=8192),
        )


def test_scan_cap_equal_to_both_caps_accepted(
    session_secret: str,
    encryption_key_b64: str,
) -> None:
    """Equality satisfies the >= invariant — the common upgrade path."""
    s = AnglerfishSettings(
        dashboard=DashboardConfig(session_secret=SecretStr(session_secret)),
        credentials=CredentialsConfig(encryption_key=SecretStr(encryption_key_b64)),
        ollama=OllamaConfig(max_response_chars=16384),
        bridge=BridgeConfig(max_input_chars=16384),
        defense=DefenseConfig(scan_max_chars=16384),
    )
    assert s.defense.scan_max_chars == 16384


def test_scan_cap_above_both_caps_accepted(
    session_secret: str,
    encryption_key_b64: str,
) -> None:
    """Scan cap can be larger than the I/O caps; defense in depth."""
    s = AnglerfishSettings(
        dashboard=DashboardConfig(session_secret=SecretStr(session_secret)),
        credentials=CredentialsConfig(encryption_key=SecretStr(encryption_key_b64)),
        ollama=OllamaConfig(max_response_chars=2048),
        bridge=BridgeConfig(max_input_chars=2048),
        defense=DefenseConfig(scan_max_chars=8192),
    )
    assert s.defense.scan_max_chars == 8192
