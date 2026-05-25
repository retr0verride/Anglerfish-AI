"""Tests for the off (passthrough) wasting strategy."""

from __future__ import annotations

from uuid import uuid4

import pytest

from anglerfish.bridge.strategies import (
    OffStrategy,
    StrategyContext,
    StrategyPreEffect,
    WastingStrategyBase,
    get_strategy,
)
from anglerfish.config.models import BridgeConfig
from anglerfish.models.session import BridgeChunk, ResponseSource


def _ctx() -> StrategyContext:
    return StrategyContext(
        session_id=uuid4(),
        command="ls",
        command_count=0,
        wasted_ms_so_far=0,
        bridge_config=BridgeConfig(),
    )


def test_off_name_is_off() -> None:
    assert OffStrategy().name == "off"


async def test_off_pre_command_returns_empty_effect() -> None:
    effect = await OffStrategy().pre_command(_ctx())
    assert effect == StrategyPreEffect()
    assert effect.pre_message is None
    assert effect.total_added_ms == 0


async def test_off_between_chunks_returns_zero() -> None:
    chunk = BridgeChunk(delta="hi", source=ResponseSource.AI, done=False)
    delay = await OffStrategy().between_chunks(_ctx(), chunk)
    assert delay == 0.0


def test_get_strategy_off_returns_off_instance() -> None:
    assert isinstance(get_strategy("off"), OffStrategy)


def test_get_strategy_aggressive_routes_to_off_until_slice_63() -> None:
    """Slice 6.2 routes aggressive to OffStrategy until 6.3 lands.

    The name is accepted (no ValueError) so dashboard-driven strategy
    changes do not 500 the bridge during the slice-2 deploy window;
    slice 6.3 ships the real aggressive implementation.
    """
    assert isinstance(get_strategy("aggressive"), OffStrategy)


def test_get_strategy_unknown_name_raises_value_error() -> None:
    with pytest.raises(ValueError, match="unknown wasting strategy"):
        get_strategy("does-not-exist")


def test_off_strategy_is_a_wasting_strategy_base() -> None:
    assert isinstance(OffStrategy(), WastingStrategyBase)
