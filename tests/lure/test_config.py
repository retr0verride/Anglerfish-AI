"""Tests for :class:`anglerfish.lure.config.LureConfig`."""

from __future__ import annotations

import ipaddress

import pytest
from pydantic import HttpUrl, ValidationError

from anglerfish.lure.config import LureConfig


def test_defaults_load_clean() -> None:
    cfg = LureConfig()
    assert cfg.enabled is True  # default opt-out: honeypot listener is the product
    assert str(cfg.listen_host) == "0.0.0.0"
    assert cfg.listen_port == 2222
    assert cfg.hostname == "srv-prod-01"
    assert cfg.banner_openssh_version == "9.2p1"
    assert cfg.max_command_chars == 1024
    assert cfg.history_window == 200
    assert cfg.per_ip_max_concurrent_connections == 3
    assert cfg.per_ip_max_connections_per_minute == 30
    assert str(cfg.bridge_base_url) == "http://127.0.0.1:8421/"
    assert cfg.bridge_request_timeout_s == pytest.approx(30.0)
    assert cfg.bridge_connect_timeout_s == pytest.approx(2.0)
    assert cfg.timing_jitter_enabled is True
    assert cfg.timing_jitter_floor_ms == 200
    assert cfg.timing_jitter_ceiling_ms == 3500
    assert cfg.keepalive_interval_s == 60
    assert cfg.keepalive_count_max == 3
    assert cfg.http_lure_enabled is False
    assert cfg.http_lure_listen_port == 8080


def test_extra_fields_forbidden() -> None:
    with pytest.raises(ValidationError):
        LureConfig(unknown_field=42)  # type: ignore[call-arg]


def test_frozen() -> None:
    cfg = LureConfig()
    with pytest.raises(ValidationError):
        cfg.enabled = True  # type: ignore[misc]


def test_http_lure_port_collision_rejected() -> None:
    with pytest.raises(ValidationError, match="http_lure_listen_port"):
        LureConfig(http_lure_enabled=True, http_lure_listen_port=2222, listen_port=2222)


def test_http_lure_port_difference_accepted() -> None:
    cfg = LureConfig(http_lure_enabled=True, http_lure_listen_port=8080, listen_port=2222)
    assert cfg.http_lure_enabled is True


def test_jitter_floor_above_ceiling_rejected() -> None:
    with pytest.raises(ValidationError, match="timing_jitter_floor_ms"):
        LureConfig(timing_jitter_floor_ms=500, timing_jitter_ceiling_ms=200)


def test_jitter_bootstrap_min_above_max_rejected() -> None:
    with pytest.raises(ValidationError, match="bootstrap"):
        LureConfig(
            timing_jitter_bootstrap_min_ms=1800,
            timing_jitter_bootstrap_max_ms=800,
        )


def test_jitter_equal_bounds_accepted() -> None:
    cfg = LureConfig(
        timing_jitter_floor_ms=500,
        timing_jitter_ceiling_ms=500,
        timing_jitter_bootstrap_min_ms=800,
        timing_jitter_bootstrap_max_ms=800,
    )
    assert cfg.timing_jitter_floor_ms == cfg.timing_jitter_ceiling_ms == 500


def test_max_command_chars_bounds() -> None:
    LureConfig(max_command_chars=1)
    LureConfig(max_command_chars=8192)
    with pytest.raises(ValidationError):
        LureConfig(max_command_chars=0)
    with pytest.raises(ValidationError):
        LureConfig(max_command_chars=8193)


def test_per_ip_limits_bounds() -> None:
    LureConfig(per_ip_max_concurrent_connections=1, per_ip_max_connections_per_minute=1)
    LureConfig(
        per_ip_max_concurrent_connections=100,
        per_ip_max_connections_per_minute=600,
    )
    with pytest.raises(ValidationError):
        LureConfig(per_ip_max_concurrent_connections=0)
    with pytest.raises(ValidationError):
        LureConfig(per_ip_max_concurrent_connections=101)


def test_keepalive_zero_disables() -> None:
    cfg = LureConfig(keepalive_interval_s=0)
    assert cfg.keepalive_interval_s == 0


def test_hostname_max_63_chars() -> None:
    LureConfig(hostname="a" * 63)
    with pytest.raises(ValidationError):
        LureConfig(hostname="a" * 64)


def test_listen_host_accepts_ipv4_literal() -> None:
    cfg = LureConfig(listen_host=ipaddress.IPv4Address("192.0.2.10"))
    assert str(cfg.listen_host) == "192.0.2.10"


def test_listen_host_accepts_ipv6_literal() -> None:
    cfg = LureConfig(listen_host=ipaddress.IPv6Address("2001:db8::1"))
    assert str(cfg.listen_host) == "2001:db8::1"


def test_listen_port_must_be_in_tcp_range() -> None:
    LureConfig(listen_port=0)  # ephemeral / kernel-assigned, allowed
    LureConfig(listen_port=1)
    LureConfig(listen_port=65535)
    with pytest.raises(ValidationError):
        LureConfig(listen_port=-1)
    with pytest.raises(ValidationError):
        LureConfig(listen_port=65536)


def test_bridge_url_is_typed() -> None:
    cfg = LureConfig(bridge_base_url=HttpUrl("http://127.0.0.1:9000/"))
    assert cfg.bridge_base_url.host == "127.0.0.1"
    assert cfg.bridge_base_url.port == 9000
