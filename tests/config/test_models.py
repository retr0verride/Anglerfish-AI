"""Tests for :mod:`anglerfish.config.models`."""

from __future__ import annotations

import base64
import ipaddress
from pathlib import Path

import pytest
from pydantic import HttpUrl, SecretStr, ValidationError

from anglerfish.config.models import (
    BridgeConfig,
    CowrieConfig,
    CredentialsConfig,
    DashboardConfig,
    DefenseConfig,
    FingerprintConfig,
    GeoConfig,
    LogLevel,
    OllamaConfig,
    RateLimitConfig,
    SplunkConfig,
    ThreatConfig,
)

# ---------------------------------------------------------------------------
# LogLevel
# ---------------------------------------------------------------------------


def test_log_level_members() -> None:
    assert LogLevel.DEBUG == "DEBUG"
    assert LogLevel.INFO == "INFO"
    assert LogLevel.WARNING == "WARNING"
    assert LogLevel.ERROR == "ERROR"
    assert LogLevel.CRITICAL == "CRITICAL"


# ---------------------------------------------------------------------------
# OllamaConfig — endpoint validation is the security-critical surface
# ---------------------------------------------------------------------------


def test_ollama_defaults_are_loopback() -> None:
    cfg = OllamaConfig()
    assert cfg.base_url.host == "127.0.0.1"
    assert cfg.model == "qwen3:14b"
    assert cfg.trusted_remote_host is None


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1:11434/",
        "http://127.0.0.7:11434/",
        "http://localhost:11434/",
        "http://[::1]:11434/",
    ],
)
def test_ollama_accepts_loopback_endpoints(url: str) -> None:
    cfg = OllamaConfig(base_url=HttpUrl(url))
    assert cfg.base_url.host is not None


def test_ollama_rejects_non_loopback_without_trusted_host() -> None:
    with pytest.raises(ValidationError) as exc:
        OllamaConfig(base_url=HttpUrl("http://10.0.0.5:11434/"))
    assert "not loopback" in str(exc.value)


def test_ollama_rejects_arbitrary_hostname() -> None:
    with pytest.raises(ValidationError) as exc:
        OllamaConfig(base_url=HttpUrl("http://evil.example.com:11434/"))
    assert "not loopback" in str(exc.value)


def test_ollama_accepts_matching_trusted_remote_host() -> None:
    cfg = OllamaConfig(
        base_url=HttpUrl("http://10.0.0.5:11434/"),
        trusted_remote_host=ipaddress.ip_address("10.0.0.5"),
    )
    assert cfg.base_url.host == "10.0.0.5"
    assert str(cfg.trusted_remote_host) == "10.0.0.5"


def test_ollama_rejects_mismatched_trusted_remote_host() -> None:
    with pytest.raises(ValidationError) as exc:
        OllamaConfig(
            base_url=HttpUrl("http://10.0.0.5:11434/"),
            trusted_remote_host=ipaddress.ip_address("10.0.0.6"),
        )
    assert "does not match trusted_remote_host" in str(exc.value)


def test_ollama_rejects_hostname_even_with_trusted_remote_host_set() -> None:
    with pytest.raises(ValidationError) as exc:
        OllamaConfig(
            base_url=HttpUrl("http://gpu.example.com:11434/"),
            trusted_remote_host=ipaddress.ip_address("10.0.0.5"),
        )
    assert "not an IP literal" in str(exc.value)


def test_ollama_rejects_zero_address() -> None:
    with pytest.raises(ValidationError):
        OllamaConfig(base_url=HttpUrl("http://0.0.0.0:11434/"))


def test_ollama_field_bounds() -> None:
    with pytest.raises(ValidationError):
        OllamaConfig(temperature=-0.1)
    with pytest.raises(ValidationError):
        OllamaConfig(temperature=2.5)
    with pytest.raises(ValidationError):
        OllamaConfig(max_response_tokens=0)
    with pytest.raises(ValidationError):
        OllamaConfig(max_response_chars=0)
    with pytest.raises(ValidationError):
        OllamaConfig(request_timeout_s=0.0)


def test_ollama_is_frozen() -> None:
    cfg = OllamaConfig()
    with pytest.raises(ValidationError):
        cfg.model = "other:1b"  # type: ignore[misc]


def test_ollama_extra_fields_forbidden() -> None:
    with pytest.raises(ValidationError):
        OllamaConfig(unknown=1)  # type: ignore[call-arg]


# ---------------------------------------------------------------------------
# SplunkConfig
# ---------------------------------------------------------------------------


def test_splunk_disabled_by_default() -> None:
    cfg = SplunkConfig()
    assert cfg.enabled is False
    assert cfg.hec_url is None
    assert cfg.hec_token is None


def test_splunk_enabled_requires_url_and_token() -> None:
    with pytest.raises(ValidationError) as exc:
        SplunkConfig(enabled=True)
    assert "hec_url" in str(exc.value)


def test_splunk_enabled_with_token_no_url_fails() -> None:
    with pytest.raises(ValidationError):
        SplunkConfig(enabled=True, hec_token=SecretStr("x"))


def test_splunk_enabled_fully_populated_passes() -> None:
    cfg = SplunkConfig(
        enabled=True,
        hec_url=HttpUrl("https://splunk.internal:8088/services/collector/event"),
        hec_token=SecretStr("abc"),
    )
    assert cfg.enabled is True


# ---------------------------------------------------------------------------
# CowrieConfig
# ---------------------------------------------------------------------------


def test_cowrie_defaults() -> None:
    cfg = CowrieConfig()
    assert cfg.ssh_listen_port == 2222
    assert cfg.telnet_listen_port == 2223


def test_cowrie_ports_must_differ() -> None:
    with pytest.raises(ValidationError) as exc:
        CowrieConfig(ssh_listen_port=2222, telnet_listen_port=2222)
    assert "must be different" in str(exc.value)


@pytest.mark.parametrize(
    "hostname",
    ["", "-foo", "foo-", "_bad", "a" * 64, "has spaces"],
)
def test_cowrie_invalid_hostnames(hostname: str) -> None:
    with pytest.raises(ValidationError):
        CowrieConfig(hostname=hostname)


@pytest.mark.parametrize("hostname", ["srv-01", "host", "h", "a-b-c-d", "abc123"])
def test_cowrie_valid_hostnames(hostname: str) -> None:
    cfg = CowrieConfig(hostname=hostname)
    assert cfg.hostname == hostname


# ---------------------------------------------------------------------------
# DashboardConfig
# ---------------------------------------------------------------------------


def test_dashboard_requires_session_secret() -> None:
    with pytest.raises(ValidationError):
        DashboardConfig()  # type: ignore[call-arg]


def test_dashboard_secret_must_be_long_enough() -> None:
    with pytest.raises(ValidationError) as exc:
        DashboardConfig(session_secret=SecretStr("short"))
    assert "at least 32" in str(exc.value)


def test_dashboard_secret_accepted() -> None:
    cfg = DashboardConfig(session_secret=SecretStr("x" * 32))
    assert cfg.session_secret.get_secret_value() == "x" * 32
    assert cfg.port == 8420


# ---------------------------------------------------------------------------
# BridgeConfig
# ---------------------------------------------------------------------------


def test_bridge_defaults() -> None:
    cfg = BridgeConfig()
    assert cfg.fake_hostname == "srv-prod-01"
    assert cfg.fake_username == "root"
    assert cfg.fake_cwd == "/root"
    assert cfg.enable_fallback is True


def test_bridge_invalid_hostname() -> None:
    with pytest.raises(ValidationError):
        BridgeConfig(fake_hostname="bad_hostname")


def test_bridge_invalid_cwd() -> None:
    with pytest.raises(ValidationError) as exc:
        BridgeConfig(fake_cwd="not-absolute")
    assert "absolute" in str(exc.value)


# ---------------------------------------------------------------------------
# RateLimitConfig
# ---------------------------------------------------------------------------


def test_rate_limit_defaults() -> None:
    cfg = RateLimitConfig()
    assert cfg.max_concurrent_requests == 8
    assert cfg.requests_per_session_per_minute == 30


def test_rate_limit_bounds() -> None:
    with pytest.raises(ValidationError):
        RateLimitConfig(max_concurrent_requests=0)
    with pytest.raises(ValidationError):
        RateLimitConfig(queue_timeout_s=0.0)


# ---------------------------------------------------------------------------
# ThreatConfig
# ---------------------------------------------------------------------------


def test_threat_defaults() -> None:
    cfg = ThreatConfig()
    assert cfg.alert_threshold == 70
    assert cfg.alert_webhook_url is None


def test_threat_threshold_bounds() -> None:
    with pytest.raises(ValidationError):
        ThreatConfig(alert_threshold=-1)
    with pytest.raises(ValidationError):
        ThreatConfig(alert_threshold=101)


def test_threat_webhook_https_hostname_accepted() -> None:
    cfg = ThreatConfig(
        alert_webhook_url=HttpUrl("https://hooks.slack.com/services/T/B/X"),
    )
    assert cfg.alert_webhook_url is not None
    assert cfg.alert_webhook_url.host == "hooks.slack.com"


def test_threat_webhook_rejects_http_scheme() -> None:
    with pytest.raises(ValidationError, match="not 'https'"):
        ThreatConfig(
            alert_webhook_url=HttpUrl("http://hooks.slack.com/services/T/B/X"),
        )


def test_threat_webhook_rejects_loopback_ip_literal() -> None:
    with pytest.raises(ValidationError, match="private/loopback/link-local"):
        ThreatConfig(alert_webhook_url=HttpUrl("https://127.0.0.1/hook"))


def test_threat_webhook_rejects_private_ip_literal() -> None:
    with pytest.raises(ValidationError, match="private/loopback/link-local"):
        ThreatConfig(alert_webhook_url=HttpUrl("https://10.0.0.5/hook"))
    with pytest.raises(ValidationError, match="private/loopback/link-local"):
        ThreatConfig(alert_webhook_url=HttpUrl("https://192.168.1.1/hook"))
    with pytest.raises(ValidationError, match="private/loopback/link-local"):
        ThreatConfig(alert_webhook_url=HttpUrl("https://172.16.0.1/hook"))


def test_threat_webhook_rejects_link_local_ip_literal() -> None:
    with pytest.raises(ValidationError, match="private/loopback/link-local"):
        ThreatConfig(alert_webhook_url=HttpUrl("https://169.254.169.254/hook"))


def test_threat_webhook_rejects_loopback_ipv6_literal() -> None:
    with pytest.raises(ValidationError, match="private/loopback/link-local"):
        ThreatConfig(alert_webhook_url=HttpUrl("https://[::1]/hook"))


# ---------------------------------------------------------------------------
# GeoConfig
# ---------------------------------------------------------------------------


def test_geo_enabled_false_by_default() -> None:
    cfg = GeoConfig()
    assert cfg.enabled is False


def test_geo_enabled_when_any_path_set() -> None:
    cfg = GeoConfig(city_db_path=Path("/tmp/x.mmdb"))
    assert cfg.enabled is True
    cfg2 = GeoConfig(asn_db_path=Path("/tmp/y.mmdb"))
    assert cfg2.enabled is True


def test_geo_maxmind_license_key_accepts_alphanumeric() -> None:
    cfg = GeoConfig(maxmind_license_key=SecretStr("ABCD1234EFGH5678"))
    assert cfg.maxmind_license_key is not None
    assert cfg.maxmind_license_key.get_secret_value() == "ABCD1234EFGH5678"


def test_geo_maxmind_license_key_rejects_non_alphanumeric() -> None:
    with pytest.raises(ValidationError, match="alphanumeric"):
        GeoConfig(maxmind_license_key=SecretStr("bad key with spaces"))


def test_geo_maxmind_license_key_rejects_too_short() -> None:
    with pytest.raises(ValidationError, match="alphanumeric"):
        GeoConfig(maxmind_license_key=SecretStr("short"))


# ---------------------------------------------------------------------------
# FingerprintConfig
# ---------------------------------------------------------------------------


def test_fingerprint_defaults() -> None:
    cfg = FingerprintConfig()
    assert cfg.tor_exit_refresh_interval_s == 3600.0


# ---------------------------------------------------------------------------
# CredentialsConfig
# ---------------------------------------------------------------------------


def test_credentials_requires_encryption_key() -> None:
    with pytest.raises(ValidationError):
        CredentialsConfig()  # type: ignore[call-arg]


def test_credentials_rejects_invalid_base64() -> None:
    with pytest.raises(ValidationError) as exc:
        CredentialsConfig(encryption_key=SecretStr("not!base64!"))
    assert "base64" in str(exc.value)


def test_credentials_rejects_wrong_length() -> None:
    too_short = base64.b64encode(b"\x00" * 16).decode("ascii")
    with pytest.raises(ValidationError) as exc:
        CredentialsConfig(encryption_key=SecretStr(too_short))
    assert "32 bytes" in str(exc.value)


def test_credentials_accepts_32_byte_key() -> None:
    key = base64.b64encode(b"\x07" * 32).decode("ascii")
    cfg = CredentialsConfig(encryption_key=SecretStr(key))
    assert cfg.encryption_key.get_secret_value() == key


# ---------------------------------------------------------------------------
# DefenseConfig — Stage 1 LLM defense layer
# ---------------------------------------------------------------------------


# A real SHA256 (lowercase hex, 64 chars) used by several tests below.
_VALID_SHA256 = "a" * 64
_VALID_SHA256_PREFIXED = "sha256:" + ("b" * 64)


def test_defense_defaults() -> None:
    cfg = DefenseConfig()
    assert cfg.output_filter_enabled is True
    assert cfg.injection_filter_enabled is True
    assert cfg.injection_threshold == pytest.approx(0.7)
    assert cfg.scan_max_chars == 8192
    assert cfg.model_expected_hash is None
    assert cfg.pattern_overrides_path is None
    assert cfg.ollama_manifest_dir is None


def test_defense_scan_max_chars_bounds() -> None:
    # Stage 1.8.5: minimum 512 is enough to scan a sensible command;
    # going below would shrink the scan window past useful range.
    DefenseConfig(scan_max_chars=512)
    DefenseConfig(scan_max_chars=65536)
    with pytest.raises(ValidationError):
        DefenseConfig(scan_max_chars=511)
    with pytest.raises(ValidationError):
        DefenseConfig(scan_max_chars=0)
    with pytest.raises(ValidationError):
        DefenseConfig(scan_max_chars=65537)


def test_defense_scan_max_chars_accepts_custom() -> None:
    cfg = DefenseConfig(scan_max_chars=16384)
    assert cfg.scan_max_chars == 16384


def test_defense_threshold_in_range() -> None:
    DefenseConfig(injection_threshold=0.0)
    DefenseConfig(injection_threshold=1.0)
    DefenseConfig(injection_threshold=0.95)


def test_defense_threshold_out_of_range_rejected() -> None:
    with pytest.raises(ValidationError):
        DefenseConfig(injection_threshold=-0.01)
    with pytest.raises(ValidationError):
        DefenseConfig(injection_threshold=1.01)


def test_defense_filters_can_be_disabled() -> None:
    cfg = DefenseConfig(output_filter_enabled=False, injection_filter_enabled=False)
    assert cfg.output_filter_enabled is False
    assert cfg.injection_filter_enabled is False


# A manifest dir for hash-accept tests; the value never has to exist
# since the cross-field validator only requires the field be set.
_MANIFEST_DIR = Path("/usr/share/ollama/.ollama/models/manifests")


def test_defense_model_hash_accepts_bare_sha256() -> None:
    cfg = DefenseConfig(
        model_expected_hash=SecretStr(_VALID_SHA256),
        ollama_manifest_dir=_MANIFEST_DIR,
    )
    assert cfg.model_expected_hash is not None
    assert cfg.model_expected_hash.get_secret_value() == _VALID_SHA256


def test_defense_model_hash_accepts_sha256_prefix() -> None:
    cfg = DefenseConfig(
        model_expected_hash=SecretStr(_VALID_SHA256_PREFIXED),
        ollama_manifest_dir=_MANIFEST_DIR,
    )
    assert cfg.model_expected_hash is not None
    # The validator preserves the raw form; downstream code normalizes.
    assert cfg.model_expected_hash.get_secret_value() == _VALID_SHA256_PREFIXED


def test_defense_model_hash_rejects_wrong_length() -> None:
    with pytest.raises(ValidationError, match="SHA256 hex"):
        DefenseConfig(model_expected_hash=SecretStr("a" * 63))
    with pytest.raises(ValidationError, match="SHA256 hex"):
        DefenseConfig(model_expected_hash=SecretStr("a" * 65))
    with pytest.raises(ValidationError, match="SHA256 hex"):
        DefenseConfig(model_expected_hash=SecretStr("sha256:" + "a" * 63))


def test_defense_model_hash_rejects_non_hex() -> None:
    with pytest.raises(ValidationError, match="SHA256 hex"):
        DefenseConfig(model_expected_hash=SecretStr("g" * 64))  # 'g' isn't hex
    with pytest.raises(ValidationError, match="SHA256 hex"):
        DefenseConfig(model_expected_hash=SecretStr("z" * 64))  # 'z' isn't hex


def test_defense_model_hash_accepts_uppercase_normalized() -> None:
    # Validator normalizes case during the hex check, so uppercase is
    # accepted. Operators who paste from `jq` get lowercase by default;
    # accepting both prevents copy-paste friction with no security loss
    # (the underlying hash is the same value either way).
    cfg = DefenseConfig(
        model_expected_hash=SecretStr("A" * 64),
        ollama_manifest_dir=_MANIFEST_DIR,
    )
    assert cfg.model_expected_hash is not None


def test_defense_model_hash_rejects_empty() -> None:
    with pytest.raises(ValidationError, match="SHA256 hex"):
        DefenseConfig(model_expected_hash=SecretStr(""))


def test_defense_pattern_overrides_path_optional() -> None:
    cfg = DefenseConfig(pattern_overrides_path=Path("/etc/anglerfish/overrides.toml"))
    assert cfg.pattern_overrides_path == Path("/etc/anglerfish/overrides.toml")


def test_defense_ollama_manifest_dir_optional_alone() -> None:
    """Setting only the manifest dir (no hash) is fine."""
    cfg = DefenseConfig(
        ollama_manifest_dir=Path("/usr/share/ollama/.ollama/models/manifests"),
    )
    assert cfg.ollama_manifest_dir == Path(
        "/usr/share/ollama/.ollama/models/manifests",
    )
    assert cfg.model_expected_hash is None


def test_defense_hash_requires_manifest_dir() -> None:
    """Cross-field invariant: if hash is set, manifest dir must be too."""
    with pytest.raises(ValidationError, match="ollama_manifest_dir"):
        DefenseConfig(model_expected_hash=SecretStr(_VALID_SHA256))


def test_defense_hash_with_manifest_dir_accepted() -> None:
    cfg = DefenseConfig(
        model_expected_hash=SecretStr(_VALID_SHA256),
        ollama_manifest_dir=_MANIFEST_DIR,
    )
    assert cfg.model_expected_hash is not None
    assert cfg.ollama_manifest_dir == _MANIFEST_DIR


def test_defense_frozen() -> None:
    cfg = DefenseConfig()
    with pytest.raises(ValidationError):
        cfg.output_filter_enabled = False  # type: ignore[misc]


def test_defense_rejects_unknown_fields() -> None:
    with pytest.raises(ValidationError):
        DefenseConfig(secret_setting="oops")  # type: ignore[call-arg]
