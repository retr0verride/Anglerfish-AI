"""Light time-wasting strategy.

Adds small, attacker-imperceptible delays around the LLM stream:

* 5% probability of a short pre-message ("Loading...", "One
  moment.", "Working...") with 500 ms delay before the message and
  300 ms before the LLM call begins. The remaining 95% of commands
  pass through with no pre-effect.
* 50-150 ms random delay between every AI chunk in the streaming
  response. Pacing feels notably slower than the off strategy but
  the response content is unchanged.

Expected per-session impact: +15-30% wall-clock vs the off
strategy. The 5% pre-message rate keeps the pattern from being a
reliable fingerprint while still contributing observable dwell
time. Per the Stage 6 design, randomness is seeded with
``(session_id, command_count)`` so an attacker who reconnects
mid-session sees the same pattern across a bridge restart.
"""

from __future__ import annotations

import random

from anglerfish.bridge.strategies.base import (
    StrategyContext,
    StrategyPreEffect,
    WastingStrategyBase,
)
from anglerfish.models.session import BridgeChunk

__all__ = ["LightStrategy"]


_PRE_MESSAGE_RATE = 0.05
_PRE_MESSAGES = (
    "Loading...\n",
    "One moment.\n",
    "Working...\n",
)
_PRE_MESSAGE_DELAY_MS = 500
_PRE_DELAY_MS = 300
_CHUNK_DELAY_MIN_S = 0.05
_CHUNK_DELAY_MAX_S = 0.15


class LightStrategy(WastingStrategyBase):
    """Light wasting: occasional pre-message, small inter-chunk delays."""

    @property
    def name(self) -> str:
        return "light"

    async def pre_command(self, ctx: StrategyContext) -> StrategyPreEffect:
        rng = _rng_for(ctx)
        if rng.random() >= _PRE_MESSAGE_RATE:
            return StrategyPreEffect()
        message = rng.choice(_PRE_MESSAGES)
        return StrategyPreEffect(
            pre_message=message,
            pre_message_delay_ms=_PRE_MESSAGE_DELAY_MS,
            pre_delay_ms=_PRE_DELAY_MS,
        )

    async def between_chunks(
        self,
        ctx: StrategyContext,
        chunk: BridgeChunk,
    ) -> float:
        del chunk  # delay is independent of chunk content
        rng = _rng_for(ctx)
        return rng.uniform(_CHUNK_DELAY_MIN_S, _CHUNK_DELAY_MAX_S)


def _rng_for(ctx: StrategyContext) -> random.Random:
    """Build a per-command :class:`random.Random` seeded deterministically."""
    seed = f"{ctx.session_id}:{ctx.command_count}"
    return random.Random(seed)  # noqa: S311 - non-cryptographic timing jitter
