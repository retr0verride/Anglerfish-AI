"""Per-IP token-bucket rate limiter for login attempts.

bcrypt's cost factor already throttles credential checks (each
``verify_password`` call burns ~100 ms of CPU on the dashboard's
core), but a slow attacker can still queue up parallel attempts.
The limiter here adds a short-window cap that holds even against
slow attackers and against attempts that never get as far as bcrypt
(rate-limit triggers before the password is checked).

Design choices:

* In-memory only — dashboard is a single process. Restart clears
  the buckets; the bcrypt cost still bounds the steady-state rate.
* Token bucket per ``client.host``: the client supplies neither
  ``Forwarded`` nor ``X-Forwarded-For`` by default; uvicorn's
  ``--proxy-headers`` populates ``request.client.host`` from
  ``X-Forwarded-For`` when configured. We trust that input only
  insofar as ``--proxy-headers`` is configured by the operator.
* Steady-state allowance: 5 attempts per 60 s window, with a
  burst-capacity of 5 (consistent with the steady rate). Any login —
  success *or* failure — consumes a token. Outside the window the
  bucket refills linearly. Operators only see the limit if they have
  the wrong password and panic-click.
* Records ``dashboard.login_rate_limited`` to the audit log; the
  caller passes the :class:`AuditLog` in.

Thread-safety: the dashboard is single-process async, so a simple
:class:`asyncio.Lock` suffices. The limiter is fast enough that
holding the lock per request is cheap.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Callable
from dataclasses import dataclass

__all__ = ["LoginRateLimiter", "RateLimitDecision"]


_Clock = Callable[[], float]


@dataclass(frozen=True)
class RateLimitDecision:
    """Outcome of one bucket consult."""

    allowed: bool
    retry_after_seconds: float


class LoginRateLimiter:
    """Token bucket keyed on client IP.

    Two knobs:

    * ``capacity`` — burst size (tokens available immediately).
    * ``refill_per_second`` — steady-state rate.

    Defaults give 5 attempts then a 60-second tail of one attempt
    per 12 s — generous for operators, painful for attackers.
    """

    def __init__(
        self,
        *,
        capacity: int = 5,
        refill_per_second: float = 1.0 / 12.0,
        clock: _Clock | None = None,
        max_buckets: int = 100_000,
    ) -> None:
        if capacity < 1:
            raise ValueError("capacity must be ≥ 1")
        if refill_per_second <= 0:
            raise ValueError("refill_per_second must be > 0")
        self._capacity = float(capacity)
        self._refill = refill_per_second
        # Mythos M6: bound the per-key bucket map. The dashboard login path
        # sees few IPs, but the same limiter fronts the internet-facing
        # callback receiver, where a distributed flood of distinct IPs would
        # otherwise grow this map without limit. When the cap is exceeded we
        # drop idle (fully-refilled) buckets, then hard-reset if still over.
        self._max_buckets = max_buckets
        self._buckets: dict[str, tuple[float, float]] = {}
        self._lock = asyncio.Lock()
        self._clock: _Clock = clock or time.monotonic

    def _evict_locked(self, now: float) -> None:
        if len(self._buckets) <= self._max_buckets:
            return
        # Drop buckets that have refilled to capacity (idle keys lose no
        # protection by being forgotten -- they would start full anyway).
        idle = [
            key
            for key, (tokens, last) in self._buckets.items()
            if min(self._capacity, tokens + max(0.0, now - last) * self._refill) >= self._capacity
        ]
        for key in idle:
            del self._buckets[key]
        if len(self._buckets) > self._max_buckets:
            # Sustained flood of active buckets: hard-reset to bound memory.
            self._buckets.clear()

    async def consume(self, key: str) -> RateLimitDecision:
        """Take one token from ``key``'s bucket. Always records the attempt."""
        now = self._clock()
        async with self._lock:
            self._evict_locked(now)
            tokens, last = self._buckets.get(key, (self._capacity, now))
            elapsed = max(0.0, now - last)
            tokens = min(self._capacity, tokens + elapsed * self._refill)
            if tokens >= 1.0:
                tokens -= 1.0
                self._buckets[key] = (tokens, now)
                return RateLimitDecision(allowed=True, retry_after_seconds=0.0)
            wait = (1.0 - tokens) / self._refill
            # Persist the refilled token count and the new `last`
            # timestamp so the next consult resumes from the correct
            # bucket state even though this attempt was refused.
            self._buckets[key] = (tokens, now)
            return RateLimitDecision(allowed=False, retry_after_seconds=wait)

    async def reset(self, key: str) -> None:
        """Forget the bucket for ``key`` (e.g. after a confirmed login)."""
        async with self._lock:
            self._buckets.pop(key, None)
