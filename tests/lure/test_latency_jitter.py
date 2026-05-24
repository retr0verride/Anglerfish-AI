"""Tests for :class:`anglerfish.lure.commands.LatencyJitter`."""

from __future__ import annotations

import statistics

import pytest

from anglerfish.lure.commands import LatencyJitter
from anglerfish.lure.config import LureConfig


def _cfg(**overrides: object) -> LureConfig:
    return LureConfig(**overrides)  # type: ignore[arg-type]


def test_disabled_returns_zero() -> None:
    j = LatencyJitter(_cfg(timing_jitter_enabled=False))
    assert j.sample_native_delay_ms() == 0.0


def test_bootstrap_samples_within_configured_range() -> None:
    j = LatencyJitter(
        _cfg(
            timing_jitter_bootstrap_min_ms=400,
            timing_jitter_bootstrap_max_ms=600,
        ),
    )
    for _ in range(50):
        d = j.sample_native_delay_ms()
        assert 400.0 <= d <= 600.0


def test_ewma_kicks_in_after_min_samples() -> None:
    j = LatencyJitter(
        _cfg(
            timing_jitter_floor_ms=100,
            timing_jitter_ceiling_ms=4000,
            timing_jitter_bootstrap_min_ms=2000,
            timing_jitter_bootstrap_max_ms=2000,
        ),
    )
    # Feed 5 samples at ~1000ms; subsequent samples should center
    # roughly there, far from the bootstrap 2000.
    for _ in range(20):
        j.record_bridge_latency(1000.0)
    samples = [j.sample_native_delay_ms() for _ in range(200)]
    median = statistics.median(samples)
    # Log-normal centered on log(1000) gives median ~1000ms.
    assert 500.0 < median < 2000.0


def test_ewma_respects_floor() -> None:
    j = LatencyJitter(
        _cfg(
            timing_jitter_floor_ms=300,
            timing_jitter_ceiling_ms=4000,
        ),
    )
    for _ in range(20):
        j.record_bridge_latency(50.0)  # very low
    for _ in range(100):
        d = j.sample_native_delay_ms()
        assert d >= 300.0


def test_ewma_respects_ceiling() -> None:
    j = LatencyJitter(
        _cfg(
            timing_jitter_floor_ms=100,
            timing_jitter_ceiling_ms=2000,
        ),
    )
    for _ in range(20):
        j.record_bridge_latency(10_000.0)  # huge
    for _ in range(100):
        d = j.sample_native_delay_ms()
        assert d <= 2000.0


def test_negative_latency_is_ignored() -> None:
    j = LatencyJitter(_cfg())
    j.record_bridge_latency(-5.0)
    # Still in bootstrap because nothing was actually recorded.
    d = j.sample_native_delay_ms()
    cfg = _cfg()
    assert cfg.timing_jitter_bootstrap_min_ms <= d <= cfg.timing_jitter_bootstrap_max_ms


def test_record_clamps_to_ceiling() -> None:
    j = LatencyJitter(
        _cfg(
            timing_jitter_ceiling_ms=500,
        ),
    )
    j.record_bridge_latency(50_000.0)
    # Internal state should now reflect ~500, not 50000.
    # We test via the sampled values staying within bounds.
    for _ in range(20):
        j.record_bridge_latency(50_000.0)
    samples = [j.sample_native_delay_ms() for _ in range(50)]
    assert max(samples) <= 500.0


async def test_sleep_native_actually_sleeps(monkeypatch: pytest.MonkeyPatch) -> None:
    slept: list[float] = []

    async def _fake_sleep(seconds: float) -> None:
        slept.append(seconds)

    monkeypatch.setattr("asyncio.sleep", _fake_sleep)
    j = LatencyJitter(
        _cfg(
            timing_jitter_bootstrap_min_ms=200,
            timing_jitter_bootstrap_max_ms=200,
        ),
    )
    await j.sleep_native()
    assert slept == [0.2]


async def test_sleep_native_no_op_when_disabled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    slept: list[float] = []

    async def _fake_sleep(seconds: float) -> None:
        slept.append(seconds)

    monkeypatch.setattr("asyncio.sleep", _fake_sleep)
    j = LatencyJitter(_cfg(timing_jitter_enabled=False))
    await j.sleep_native()
    assert slept == []
