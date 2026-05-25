"""Tests for :class:`anglerfish.bridge.strategies.LightStrategy`."""

from __future__ import annotations

from uuid import UUID

from anglerfish.bridge.strategies import (
    LightStrategy,
    StrategyContext,
    get_strategy,
)
from anglerfish.bridge.strategies.light import (
    _CHUNK_DELAY_MAX_S,
    _CHUNK_DELAY_MIN_S,
    _PRE_DELAY_MS,
    _PRE_MESSAGE_DELAY_MS,
    _PRE_MESSAGE_RATE,
    _PRE_MESSAGES,
)
from anglerfish.config.models import BridgeConfig
from anglerfish.models.session import BridgeChunk, ResponseSource

_FIXED_SESSION = UUID("00000000-0000-0000-0000-000000000001")


def _ctx(*, command: str = "ls", command_count: int = 0) -> StrategyContext:
    return StrategyContext(
        session_id=_FIXED_SESSION,
        command=command,
        command_count=command_count,
        wasted_ms_so_far=0,
        bridge_config=BridgeConfig(),
    )


def test_light_name_is_light() -> None:
    assert LightStrategy().name == "light"


def test_get_strategy_light_returns_light() -> None:
    assert isinstance(get_strategy("light"), LightStrategy)


async def test_pre_command_is_deterministic_for_same_seed() -> None:
    s = LightStrategy()
    a = await s.pre_command(_ctx(command_count=7))
    b = await s.pre_command(_ctx(command_count=7))
    assert a == b


async def test_pre_command_differs_across_command_counts() -> None:
    """Different command_count seeds produce different per-call randomness."""
    s = LightStrategy()
    effects = [await s.pre_command(_ctx(command_count=n)) for n in range(50)]
    # Not every call needs to produce a pre-message; we just need the
    # set of distinct effects to be > 1 (i.e. the seeding is not stuck).
    distinct = {(e.pre_message, e.pre_message_delay_ms, e.pre_delay_ms) for e in effects}
    assert len(distinct) >= 2


async def test_pre_command_rate_is_near_five_percent() -> None:
    """5% pre-message rate over 1000 deterministic samples."""
    s = LightStrategy()
    fires = 0
    for n in range(1000):
        effect = await s.pre_command(_ctx(command_count=n))
        if effect.pre_message is not None:
            fires += 1
    # Allow plenty of slack so the test is robust across random.Random
    # implementations. Expected ~50; assert within 25..90.
    assert 25 <= fires <= 90, fires


async def test_pre_command_when_fires_uses_known_template() -> None:
    s = LightStrategy()
    # Find a command_count where the pre-message fires (deterministic sweep).
    for n in range(200):
        effect = await s.pre_command(_ctx(command_count=n))
        if effect.pre_message is not None:
            assert effect.pre_message in _PRE_MESSAGES
            assert effect.pre_message_delay_ms == _PRE_MESSAGE_DELAY_MS
            assert effect.pre_delay_ms == _PRE_DELAY_MS
            return
    msg = f"pre-message never fired in 200 samples; rate too low (expected ~{_PRE_MESSAGE_RATE})"
    raise AssertionError(msg)


async def test_between_chunks_returns_in_documented_range() -> None:
    s = LightStrategy()
    chunk = BridgeChunk(delta="x", source=ResponseSource.AI, done=False)
    for n in range(50):
        delay = await s.between_chunks(_ctx(command_count=n), chunk)
        assert _CHUNK_DELAY_MIN_S <= delay <= _CHUNK_DELAY_MAX_S


async def test_between_chunks_is_deterministic_for_same_seed() -> None:
    s = LightStrategy()
    chunk = BridgeChunk(delta="x", source=ResponseSource.AI, done=False)
    a = await s.between_chunks(_ctx(command_count=3), chunk)
    b = await s.between_chunks(_ctx(command_count=3), chunk)
    assert a == b
