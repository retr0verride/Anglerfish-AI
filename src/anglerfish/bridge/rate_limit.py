"""Async rate-limiting primitives for the bridge.

Two concerns are addressed:

1. The total CPU/GPU available to Ollama is finite — we cap the number
   of concurrent requests in flight regardless of which session they
   came from.
2. A single attacker must not be able to monopolise inference by piping
   a flood of commands at the honeypot — each session gets its own
   token bucket.

When either limit is hit the bridge raises a :class:`BridgeError`
subclass; the service catches that and falls back to scripted
responses, so the attacker still sees a shell-shaped reply.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from uuid import UUID

from anglerfish.bridge.errors import GlobalQueueTimeoutError, SessionRateLimitedError
from anglerfish.config.models import RateLimitConfig

__all__ = ["BridgeRateLimiter", "TokenBucket"]


_Clock = Callable[[], float]


class TokenBucket:
    """Lazy-refill token bucket.

    The bucket starts full. Each :meth:`try_consume` adds tokens
    proportional to time elapsed since the previous call (capped at
    ``capacity``), then either deducts ``n`` tokens and returns ``True``
    or returns ``False`` without modifying the bucket.

    Refill is computed on demand — there is no background task — which
    keeps the bucket cheap and resilient to event-loop pauses.
    """

    __slots__ = ("_capacity", "_clock", "_last", "_lock", "_refill_per_second", "_tokens")

    def __init__(
        self,
        *,
        capacity: int,
        refill_per_second: float,
        clock: _Clock | None = None,
    ) -> None:
        if capacity <= 0:
            raise ValueError(f"capacity must be positive, got {capacity}")
        if refill_per_second <= 0:
            raise ValueError(
                f"refill_per_second must be positive, got {refill_per_second}",
            )
        self._capacity: int = capacity
        self._refill_per_second: float = refill_per_second
        self._clock: _Clock = clock if clock is not None else time.monotonic
        self._tokens: float = float(capacity)
        self._last: float = self._clock()
        self._lock = asyncio.Lock()

    @property
    def capacity(self) -> int:
        return self._capacity

    async def try_consume(self, n: float = 1.0) -> bool:
        """Atomically refill and try to take ``n`` tokens."""
        if n <= 0:
            raise ValueError(f"n must be positive, got {n}")
        async with self._lock:
            self._refill_locked()
            if self._tokens >= n:
                self._tokens -= n
                return True
            return False

    async def tokens(self) -> float:
        """Return the current token count, refilling lazily first."""
        async with self._lock:
            self._refill_locked()
            return self._tokens

    def _refill_locked(self) -> None:
        now = self._clock()
        elapsed = max(0.0, now - self._last)
        self._tokens = min(
            float(self._capacity),
            self._tokens + elapsed * self._refill_per_second,
        )
        self._last = now


class BridgeRateLimiter:
    """Combined global concurrency cap + per-session rate limit.

    Usage::

        limiter = BridgeRateLimiter(settings.rate_limit)
        async with limiter.slot(session_id):
            ...  # call Ollama

    Inside the context manager the global semaphore is held and the
    per-session token has been deducted. If the per-session bucket is
    empty :class:`SessionRateLimitedError` is raised before the
    semaphore is acquired. If the global semaphore cannot be acquired
    within ``queue_timeout_s``, :class:`GlobalQueueTimeoutError` is
    raised and the consumed token stays consumed (we treat the global
    queue timeout as a real attempt, not a free retry).

    Idle per-session buckets are evicted after
    ``bucket_idle_eviction_s`` seconds to keep memory bounded.
    """

    def __init__(
        self,
        config: RateLimitConfig,
        *,
        clock: _Clock | None = None,
    ) -> None:
        self._config = config
        self._clock: _Clock = clock if clock is not None else time.monotonic
        self._semaphore = asyncio.Semaphore(config.max_concurrent_requests)
        self._buckets: dict[UUID, tuple[TokenBucket, float]] = {}
        self._buckets_lock = asyncio.Lock()

    @property
    def config(self) -> RateLimitConfig:
        return self._config

    async def _bucket_for(self, session_id: UUID) -> TokenBucket:
        async with self._buckets_lock:
            self._evict_idle_locked()
            now = self._clock()
            existing = self._buckets.get(session_id)
            if existing is not None:
                bucket = existing[0]
                self._buckets[session_id] = (bucket, now)
                return bucket
            refill = self._config.requests_per_session_per_minute / 60.0
            bucket = TokenBucket(
                capacity=self._config.session_burst,
                refill_per_second=refill,
                clock=self._clock,
            )
            self._buckets[session_id] = (bucket, now)
            return bucket

    def _evict_idle_locked(self) -> None:
        now = self._clock()
        cutoff = now - self._config.bucket_idle_eviction_s
        stale = [sid for sid, (_, last) in self._buckets.items() if last < cutoff]
        for sid in stale:
            del self._buckets[sid]

    @asynccontextmanager
    async def slot(self, session_id: UUID) -> AsyncIterator[None]:
        """Acquire a global slot and consume one per-session token."""
        bucket = await self._bucket_for(session_id)
        if not await bucket.try_consume():
            raise SessionRateLimitedError(
                f"session {session_id} has exceeded its command budget",
            )
        try:
            await asyncio.wait_for(
                self._semaphore.acquire(),
                timeout=self._config.queue_timeout_s,
            )
        except TimeoutError as exc:
            raise GlobalQueueTimeoutError(
                f"could not acquire Ollama concurrency slot within {self._config.queue_timeout_s}s",
            ) from exc
        try:
            yield
        finally:
            self._semaphore.release()

    def active_session_count(self) -> int:
        """Return the number of sessions currently holding per-session buckets."""
        return len(self._buckets)
