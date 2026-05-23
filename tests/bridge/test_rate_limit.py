"""Tests for :mod:`anglerfish.bridge.rate_limit`."""

from __future__ import annotations

import asyncio
from uuid import uuid4

import pytest

from anglerfish.bridge.errors import GlobalQueueTimeoutError, SessionRateLimitedError
from anglerfish.bridge.rate_limit import BridgeRateLimiter, TokenBucket
from anglerfish.config.models import RateLimitConfig


class _FakeMonotonic:
    def __init__(self, start: float = 0.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, by: float) -> None:
        self.now += by


# ---------------------------------------------------------------------------
# TokenBucket
# ---------------------------------------------------------------------------


async def test_bucket_starts_full() -> None:
    clock = _FakeMonotonic()
    bucket = TokenBucket(capacity=5, refill_per_second=1.0, clock=clock)
    assert bucket.capacity == 5
    assert await bucket.tokens() == pytest.approx(5.0)


async def test_bucket_consume_deducts() -> None:
    clock = _FakeMonotonic()
    bucket = TokenBucket(capacity=5, refill_per_second=1.0, clock=clock)
    assert await bucket.try_consume() is True
    assert await bucket.tokens() == pytest.approx(4.0)


async def test_bucket_runs_dry_and_refills() -> None:
    clock = _FakeMonotonic()
    bucket = TokenBucket(capacity=3, refill_per_second=2.0, clock=clock)
    for _ in range(3):
        assert await bucket.try_consume() is True
    assert await bucket.try_consume() is False
    clock.advance(1.0)
    # 2 tokens added.
    assert await bucket.try_consume(2) is True
    assert await bucket.try_consume() is False


async def test_bucket_caps_at_capacity() -> None:
    clock = _FakeMonotonic()
    bucket = TokenBucket(capacity=4, refill_per_second=10.0, clock=clock)
    assert await bucket.try_consume() is True
    clock.advance(100.0)
    assert await bucket.tokens() == pytest.approx(4.0)


async def test_bucket_validates_constructor_args() -> None:
    with pytest.raises(ValueError):
        TokenBucket(capacity=0, refill_per_second=1.0)
    with pytest.raises(ValueError):
        TokenBucket(capacity=1, refill_per_second=0.0)


async def test_bucket_rejects_zero_consume() -> None:
    bucket = TokenBucket(capacity=1, refill_per_second=1.0)
    with pytest.raises(ValueError):
        await bucket.try_consume(0)


# ---------------------------------------------------------------------------
# BridgeRateLimiter
# ---------------------------------------------------------------------------


def _config(**kw: object) -> RateLimitConfig:
    defaults: dict[str, object] = {
        "max_concurrent_requests": 4,
        "requests_per_session_per_minute": 60,
        "session_burst": 5,
        "queue_timeout_s": 1.0,
        "bucket_idle_eviction_s": 300.0,
    }
    defaults.update(kw)
    return RateLimitConfig(**defaults)  # type: ignore[arg-type]


async def test_limiter_slot_round_trip() -> None:
    limiter = BridgeRateLimiter(_config())
    sid = uuid4()
    async with limiter.slot(sid):
        assert limiter.active_session_count() == 1
    async with limiter.slot(sid):
        pass
    assert limiter.active_session_count() == 1


async def test_limiter_per_session_exhaustion() -> None:
    clock = _FakeMonotonic()
    limiter = BridgeRateLimiter(
        _config(requests_per_session_per_minute=1, session_burst=1),
        clock=clock,
    )
    sid = uuid4()
    async with limiter.slot(sid):
        pass
    with pytest.raises(SessionRateLimitedError):
        async with limiter.slot(sid):
            pass


async def test_limiter_separate_sessions_isolated() -> None:
    limiter = BridgeRateLimiter(
        _config(session_burst=1, requests_per_session_per_minute=1),
    )
    sid_a, sid_b = uuid4(), uuid4()
    async with limiter.slot(sid_a):
        pass
    # B is independent and still has a full bucket.
    async with limiter.slot(sid_b):
        pass


async def test_limiter_global_queue_timeout() -> None:
    limiter = BridgeRateLimiter(
        _config(max_concurrent_requests=1, queue_timeout_s=0.05),
    )
    sid_a, sid_b = uuid4(), uuid4()

    started = asyncio.Event()
    release = asyncio.Event()

    async def holder() -> None:
        async with limiter.slot(sid_a):
            started.set()
            await release.wait()

    holder_task = asyncio.create_task(holder())
    try:
        await asyncio.wait_for(started.wait(), timeout=1.0)
        with pytest.raises(GlobalQueueTimeoutError):
            async with limiter.slot(sid_b):
                pytest.fail("should not have acquired slot")
    finally:
        release.set()
        await holder_task


async def test_limiter_evicts_idle_buckets() -> None:
    clock = _FakeMonotonic()
    limiter = BridgeRateLimiter(
        _config(bucket_idle_eviction_s=60.0),
        clock=clock,
    )
    sid = uuid4()
    async with limiter.slot(sid):
        pass
    assert limiter.active_session_count() == 1
    clock.advance(120.0)
    # Touching another session triggers the eviction sweep.
    async with limiter.slot(uuid4()):
        pass
    assert sid not in set(limiter._buckets)
