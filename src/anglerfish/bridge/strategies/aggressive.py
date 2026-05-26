"""Aggressive time-wasting strategy (delays only).

The heavier of the two operator-selectable strategies. Adds:

* 20% probability per command of a pre-message (the light set plus
  "Compiling response..." and "Resolving symbols..."), with 1200 ms
  delay before the message and 800 ms before the LLM call begins.
* 200-500 ms random delay between every AI chunk in the streaming
  response.

Expected per-session wall-clock impact: +50-100% vs the off
strategy. The pre-message rate plus the per-chunk delay is tuned
to be visibly slower than light without producing a clear pattern
an attacker can detect after a handful of commands.

Slice 6.3 ships the delay-based wasting only. The clarification
injection mode the design doc describes (5% probability of a
"did you mean X or Y?" follow-up that requires another command)
lands in slice 6.4 alongside the LLM-defense coverage for the
new injection surface.

Randomness is seeded with ``(session_id, command_count)`` so per-
command jitter is reproducible across bridge restarts and
pinnable in tests, matching :class:`LightStrategy`.
"""

from __future__ import annotations

import random

from anglerfish.bridge.strategies.base import (
    StrategyContext,
    StrategyPreEffect,
    WastingStrategyBase,
)
from anglerfish.bridge.strategies.light import _PRE_MESSAGES as _LIGHT_PRE_MESSAGES
from anglerfish.models.session import BridgeChunk

__all__ = ["AggressiveStrategy"]


_PRE_MESSAGE_RATE = 0.20
_PRE_MESSAGES = (
    *_LIGHT_PRE_MESSAGES,
    "Compiling response...\n",
    "Resolving symbols...\n",
)
_PRE_MESSAGE_DELAY_MS = 1200
_PRE_DELAY_MS = 800
_CHUNK_DELAY_MIN_S = 0.2
_CHUNK_DELAY_MAX_S = 0.5


class AggressiveStrategy(WastingStrategyBase):
    """Aggressive wasting: frequent pre-messages, larger inter-chunk delays."""

    @property
    def name(self) -> str:
        return "aggressive"

    async def pre_command(self, ctx: StrategyContext) -> StrategyPreEffect:
        rng = _rng_for(ctx)
        # Clarification injection first (slice 6.4): if the dice hit
        # AND we have not just clarified, the bridge swaps in the
        # clarification prompt template for this command. Pre-message
        # and clarification are mutually exclusive: a clarification
        # already pads the chain by an extra round-trip.
        if self._should_inject_clarification(ctx, rng):
            return StrategyPreEffect(inject_clarification=True)
        if rng.random() >= _PRE_MESSAGE_RATE:
            return StrategyPreEffect()
        message = rng.choice(_PRE_MESSAGES)
        return StrategyPreEffect(
            pre_message=message,
            pre_message_delay_ms=_PRE_MESSAGE_DELAY_MS,
            pre_delay_ms=_PRE_DELAY_MS,
        )

    @staticmethod
    def _should_inject_clarification(
        ctx: StrategyContext,
        rng: random.Random,
    ) -> bool:
        """Return True if this command should produce a clarification turn.

        Honours the one-per-chain invariant: if the prior command in
        this session was a clarification, this command always runs
        normally regardless of the dice.
        """
        prior = ctx.last_clarification_command_count
        if prior is not None and prior == ctx.command_count - 1:
            return False
        rate = ctx.bridge_config.aggressive_clarification_rate
        if rate <= 0.0:
            return False
        return rng.random() < rate

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
