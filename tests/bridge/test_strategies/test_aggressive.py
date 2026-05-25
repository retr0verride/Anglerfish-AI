"""Tests for :class:`anglerfish.bridge.strategies.AggressiveStrategy`."""

from __future__ import annotations

from uuid import UUID

from anglerfish.bridge.strategies import (
    AggressiveStrategy,
    StrategyContext,
    get_strategy,
)
from anglerfish.bridge.strategies.aggressive import (
    _CHUNK_DELAY_MAX_S,
    _CHUNK_DELAY_MIN_S,
    _PRE_DELAY_MS,
    _PRE_MESSAGE_DELAY_MS,
    _PRE_MESSAGE_RATE,
    _PRE_MESSAGES,
)
from anglerfish.config.models import BridgeConfig
from anglerfish.models.session import BridgeChunk, ResponseSource

_FIXED_SESSION = UUID("00000000-0000-0000-0000-000000000002")


def _ctx(*, command: str = "ls", command_count: int = 0) -> StrategyContext:
    return StrategyContext(
        session_id=_FIXED_SESSION,
        command=command,
        command_count=command_count,
        wasted_ms_so_far=0,
        bridge_config=BridgeConfig(),
    )


def test_aggressive_name_is_aggressive() -> None:
    assert AggressiveStrategy().name == "aggressive"


def test_get_strategy_aggressive_returns_aggressive() -> None:
    assert isinstance(get_strategy("aggressive"), AggressiveStrategy)


async def test_pre_command_is_deterministic_for_same_seed() -> None:
    s = AggressiveStrategy()
    a = await s.pre_command(_ctx(command_count=7))
    b = await s.pre_command(_ctx(command_count=7))
    assert a == b


async def test_pre_command_rate_is_near_twenty_percent() -> None:
    """20% pre-message rate over 1000 deterministic samples."""
    s = AggressiveStrategy()
    fires = 0
    for n in range(1000):
        effect = await s.pre_command(_ctx(command_count=n))
        if effect.pre_message is not None:
            fires += 1
    # Expected ~200 fires; allow generous slack for cross-Random
    # variance. 130..280 keeps the test stable while still catching
    # rate regressions of >>30%.
    assert 130 <= fires <= 280, fires


async def test_pre_command_when_fires_uses_known_template() -> None:
    s = AggressiveStrategy()
    for n in range(50):
        effect = await s.pre_command(_ctx(command_count=n))
        if effect.pre_message is not None:
            assert effect.pre_message in _PRE_MESSAGES
            assert effect.pre_message_delay_ms == _PRE_MESSAGE_DELAY_MS
            assert effect.pre_delay_ms == _PRE_DELAY_MS
            return
    msg = f"pre-message never fired in 50 samples; rate too low (expected ~{_PRE_MESSAGE_RATE})"
    raise AssertionError(msg)


async def test_pre_message_set_includes_aggressive_specific_templates() -> None:
    """Aggressive ships its own templates on top of the light set."""
    assert "Compiling response...\n" in _PRE_MESSAGES
    assert "Resolving symbols...\n" in _PRE_MESSAGES


async def test_between_chunks_returns_in_documented_range() -> None:
    s = AggressiveStrategy()
    chunk = BridgeChunk(delta="x", source=ResponseSource.AI, done=False)
    for n in range(50):
        delay = await s.between_chunks(_ctx(command_count=n), chunk)
        assert _CHUNK_DELAY_MIN_S <= delay <= _CHUNK_DELAY_MAX_S


async def test_between_chunks_is_deterministic_for_same_seed() -> None:
    s = AggressiveStrategy()
    chunk = BridgeChunk(delta="x", source=ResponseSource.AI, done=False)
    a = await s.between_chunks(_ctx(command_count=3), chunk)
    b = await s.between_chunks(_ctx(command_count=3), chunk)
    assert a == b
