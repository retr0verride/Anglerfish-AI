"""Tests for :class:`LoginRateLimiter`."""

from __future__ import annotations

import pytest

from anglerfish.dashboard.rate_limit import LoginRateLimiter


class _ManualClock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


async def test_allows_within_capacity() -> None:
    clock = _ManualClock()
    limiter = LoginRateLimiter(capacity=3, refill_per_second=0.1, clock=clock)
    for _ in range(3):
        result = await limiter.consume("203.0.113.7")
        assert result.allowed is True
        assert result.retry_after_seconds == 0.0


async def test_refuses_after_capacity_exhausted() -> None:
    clock = _ManualClock()
    limiter = LoginRateLimiter(capacity=2, refill_per_second=0.1, clock=clock)
    await limiter.consume("ip")
    await limiter.consume("ip")
    result = await limiter.consume("ip")
    assert result.allowed is False
    assert result.retry_after_seconds == pytest.approx(10.0, rel=0.01)


async def test_refills_over_time() -> None:
    clock = _ManualClock()
    limiter = LoginRateLimiter(capacity=2, refill_per_second=1.0, clock=clock)
    await limiter.consume("ip")
    await limiter.consume("ip")
    assert (await limiter.consume("ip")).allowed is False
    clock.advance(1.5)
    result = await limiter.consume("ip")
    assert result.allowed is True


async def test_keys_are_independent() -> None:
    clock = _ManualClock()
    limiter = LoginRateLimiter(capacity=1, refill_per_second=0.1, clock=clock)
    await limiter.consume("ip-a")
    assert (await limiter.consume("ip-a")).allowed is False
    # ip-b still has its first token
    assert (await limiter.consume("ip-b")).allowed is True


async def test_reset_clears_one_key() -> None:
    clock = _ManualClock()
    limiter = LoginRateLimiter(capacity=1, refill_per_second=0.1, clock=clock)
    await limiter.consume("ip-a")
    assert (await limiter.consume("ip-a")).allowed is False
    await limiter.reset("ip-a")
    assert (await limiter.consume("ip-a")).allowed is True


def test_capacity_validation() -> None:
    with pytest.raises(ValueError, match="capacity must be"):
        LoginRateLimiter(capacity=0)
    with pytest.raises(ValueError, match="refill_per_second"):
        LoginRateLimiter(refill_per_second=0)
