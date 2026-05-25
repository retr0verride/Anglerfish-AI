"""Passthrough wasting strategy.

The bridge's default when no time-wasting is wanted. Returns the
empty :class:`StrategyPreEffect` and zero inter-chunk delay so the
streaming path's wall-clock matches what Stage 5 ships.
"""

from __future__ import annotations

from anglerfish.bridge.strategies.base import (
    StrategyContext,
    StrategyPreEffect,
    WastingStrategyBase,
)
from anglerfish.models.session import BridgeChunk

__all__ = ["OffStrategy"]


class OffStrategy(WastingStrategyBase):
    """No-op strategy. Behaviour identical to a bridge without Stage 6."""

    @property
    def name(self) -> str:
        return "off"

    async def pre_command(self, ctx: StrategyContext) -> StrategyPreEffect:
        del ctx  # off strategy ignores the context
        return StrategyPreEffect()

    async def between_chunks(
        self,
        ctx: StrategyContext,
        chunk: BridgeChunk,
    ) -> float:
        del ctx, chunk
        return 0.0
