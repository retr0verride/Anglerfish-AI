"""Tests for :mod:`anglerfish.dashboard.overrides`."""

from __future__ import annotations

import base64

from pydantic import SecretStr

from anglerfish.config import AnglerfishSettings
from anglerfish.config.models import CredentialsConfig, DashboardConfig, RateLimitConfig
from anglerfish.dashboard.overrides import (
    BridgeRuntimeOverrides,
    FeatureFlagOverrides,
    RuntimeOverrides,
    build_runtime_overrides,
)


def _settings(*, max_concurrent: int = 8, rpm: int = 30) -> AnglerfishSettings:
    return AnglerfishSettings(
        dashboard=DashboardConfig(session_secret=SecretStr("x" * 40)),
        credentials=CredentialsConfig(
            encryption_key=SecretStr(base64.b64encode(b"\x07" * 32).decode("ascii")),
        ),
        rate_limit=RateLimitConfig(
            max_concurrent_requests=max_concurrent,
            requests_per_session_per_minute=rpm,
        ),
    )


def test_build_runtime_overrides_seeds_from_rate_limit() -> None:
    overrides = build_runtime_overrides(_settings(max_concurrent=16, rpm=60))
    assert overrides.bridge.max_concurrent_requests == 16
    assert overrides.bridge.requests_per_session_per_minute == 60
    assert overrides.bridge.wasting_strategy == "off"


def test_features_default_all_false() -> None:
    overrides = build_runtime_overrides(_settings())
    assert overrides.features.time_wasting is False
    assert overrides.features.engaged_persistence is False
    assert overrides.features.decoy_poisoning is False
    assert overrides.features.counter_deception is False


def test_snapshot_shape_has_provenance_fields() -> None:
    overrides = build_runtime_overrides(_settings())
    snap = overrides.snapshot()
    assert snap["applies_to"] == "dashboard_process"
    assert "Service restart reverts to env-file values" in snap["note"]
    assert "applied_at" in snap
    assert "bridge" in snap
    assert "features" in snap


def test_apply_bridge_returns_per_field_diff() -> None:
    overrides = build_runtime_overrides(_settings(max_concurrent=8, rpm=30))
    diff = overrides.apply_bridge(
        max_concurrent_requests=16,
        requests_per_session_per_minute=60,
    )
    assert diff == {
        "max_concurrent_requests": (8, 16),
        "requests_per_session_per_minute": (30, 60),
    }
    assert overrides.bridge.max_concurrent_requests == 16
    assert overrides.bridge.requests_per_session_per_minute == 60


def test_apply_bridge_no_op_when_values_unchanged() -> None:
    overrides = build_runtime_overrides(_settings(max_concurrent=8))
    diff = overrides.apply_bridge(max_concurrent_requests=8)
    assert diff == {}


def test_apply_bridge_partial_update_keeps_other_fields() -> None:
    overrides = build_runtime_overrides(_settings(max_concurrent=8, rpm=30))
    overrides.apply_bridge(max_concurrent_requests=16)
    assert overrides.bridge.requests_per_session_per_minute == 30  # untouched


def test_apply_bridge_wasting_strategy_diff() -> None:
    overrides = build_runtime_overrides(_settings())
    diff = overrides.apply_bridge(wasting_strategy="aggressive")
    assert diff == {"wasting_strategy": ("off", "aggressive")}
    assert overrides.bridge.wasting_strategy == "aggressive"


def test_apply_features_returns_per_flag_diff() -> None:
    overrides = build_runtime_overrides(_settings())
    diff = overrides.apply_features(time_wasting=True, counter_deception=True)
    assert diff == {
        "time_wasting": (False, True),
        "counter_deception": (False, True),
    }
    assert overrides.features.time_wasting is True
    assert overrides.features.counter_deception is True


def test_apply_features_no_op_when_values_unchanged() -> None:
    overrides = build_runtime_overrides(_settings())
    diff = overrides.apply_features(time_wasting=False)
    assert diff == {}


def test_applied_at_only_advances_when_diff_non_empty() -> None:
    overrides = build_runtime_overrides(_settings())
    before = overrides.applied_at
    overrides.apply_bridge(max_concurrent_requests=overrides.bridge.max_concurrent_requests)
    assert overrides.applied_at == before  # no change → no timestamp bump


def test_runtime_overrides_dataclass_round_trip() -> None:
    # Construction without the factory is supported (tests / fixtures).
    overrides = RuntimeOverrides(
        bridge=BridgeRuntimeOverrides(
            max_concurrent_requests=4,
            requests_per_session_per_minute=12,
        ),
        features=FeatureFlagOverrides(time_wasting=True),
    )
    snap = overrides.snapshot()
    assert snap["bridge"]["max_concurrent_requests"] == 4
    assert snap["features"]["time_wasting"] is True
