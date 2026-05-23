"""Tests for :mod:`anglerfish.config.settings`."""

from __future__ import annotations

import base64

import pytest
from pydantic import SecretStr, ValidationError

from anglerfish.config import AnglerfishSettings, load_settings
from anglerfish.config.models import CredentialsConfig, DashboardConfig, LogLevel


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
    assert s.defense.model_expected_hash is None


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
