"""Tests for the counter-deception strategy contract (Stage 12 slice 1).

Covers the ABC + the one concrete v1 implementation
(``ModeAwareCounterDeceptionStrategy``). Bridge and lure integration
land in slices 12.2 and 12.3.
"""

from __future__ import annotations

from uuid import uuid4

from anglerfish.bridge.strategies.counter_deception import (
    CounterDeceptionState,
    ModeAwareCounterDeceptionStrategy,
)
from anglerfish.config.models import CounterDeceptionConfig, CounterDeceptionMode
from anglerfish.llm.client import ChatMessage


def _config(**overrides: object) -> CounterDeceptionConfig:
    """Build a CounterDeceptionConfig with kwargs overrides applied."""
    base: dict[str, object] = {
        "enabled": True,
        "mode": CounterDeceptionMode.BOTH,
        "garble_paths": ("/root/.ssh/id_rsa", "/root/.aws/credentials"),
        "timebomb_cold_to_mild": 6,
        "timebomb_mild_to_severe": 16,
    }
    base.update(overrides)
    return CounterDeceptionConfig(**base)  # type: ignore[arg-type]


def _messages() -> list[ChatMessage]:
    return [
        ChatMessage(role="system", content="You are a Linux shell."),
        ChatMessage(role="user", content="ls"),
    ]


def test_strategy_name_is_mode_aware() -> None:
    strat = ModeAwareCounterDeceptionStrategy(_config())
    assert strat.name == "mode-aware"


def test_state_for_session_off_mode_returns_none() -> None:
    strat = ModeAwareCounterDeceptionStrategy(_config(mode=CounterDeceptionMode.OFF))
    assert strat.state_for_session(threat=None, session_id=uuid4()) is None


def test_state_for_session_garble_mode_has_paths_no_timebomb() -> None:
    strat = ModeAwareCounterDeceptionStrategy(_config(mode=CounterDeceptionMode.GARBLE))
    state = strat.state_for_session(threat=None, session_id=uuid4())
    assert state is not None
    assert state.mode is CounterDeceptionMode.GARBLE
    assert state.garble_paths == ("/root/.ssh/id_rsa", "/root/.aws/credentials")
    assert state.timebomb_thresholds == (0, 0)


def test_state_for_session_timebomb_mode_has_thresholds_no_paths() -> None:
    strat = ModeAwareCounterDeceptionStrategy(_config(mode=CounterDeceptionMode.TIMEBOMB))
    state = strat.state_for_session(threat=None, session_id=uuid4())
    assert state is not None
    assert state.mode is CounterDeceptionMode.TIMEBOMB
    assert state.garble_paths == ()
    assert state.timebomb_thresholds == (6, 16)


def test_state_for_session_both_mode_has_both() -> None:
    strat = ModeAwareCounterDeceptionStrategy(_config(mode=CounterDeceptionMode.BOTH))
    state = strat.state_for_session(threat=None, session_id=uuid4())
    assert state is not None
    assert state.mode is CounterDeceptionMode.BOTH
    assert state.garble_paths == ("/root/.ssh/id_rsa", "/root/.aws/credentials")
    assert state.timebomb_thresholds == (6, 16)


def test_amend_prompt_cold_band_passes_through_unchanged() -> None:
    """command_count below the cold->mild threshold: no amendment."""
    strat = ModeAwareCounterDeceptionStrategy(_config())
    state = CounterDeceptionState(
        mode=CounterDeceptionMode.TIMEBOMB,
        timebomb_thresholds=(6, 16),
    )
    messages = _messages()
    amended = strat.amend_prompt(messages=messages, command_count=0, state=state)
    assert len(amended) == len(messages)
    # Verify it's the same content, not the same list object (the strategy
    # always returns a fresh list to keep callers from mutating internals).
    assert amended is not messages
    assert [m.content for m in amended] == [m.content for m in messages]


def test_amend_prompt_mild_band_injects_one_system_message() -> None:
    """6 <= command_count < 16: appends the mild instruction."""
    strat = ModeAwareCounterDeceptionStrategy(_config())
    state = CounterDeceptionState(
        mode=CounterDeceptionMode.TIMEBOMB,
        timebomb_thresholds=(6, 16),
    )
    messages = _messages()
    amended = strat.amend_prompt(messages=messages, command_count=6, state=state)
    assert len(amended) == len(messages) + 1
    last = amended[-1]
    assert last.role == "system"
    assert "ONE small factual error" in last.content
    # Severe instruction must NOT be present in the mild band.
    assert "Two to three small factual errors" not in last.content


def test_amend_prompt_severe_band_injects_mild_and_severe() -> None:
    """command_count >= 16: appends both mild and severe instructions."""
    strat = ModeAwareCounterDeceptionStrategy(_config())
    state = CounterDeceptionState(
        mode=CounterDeceptionMode.BOTH,
        timebomb_thresholds=(6, 16),
    )
    messages = _messages()
    amended = strat.amend_prompt(messages=messages, command_count=16, state=state)
    assert len(amended) == len(messages) + 2
    mild_msg, severe_msg = amended[-2], amended[-1]
    assert mild_msg.role == "system"
    assert severe_msg.role == "system"
    assert "ONE small factual error" in mild_msg.content
    assert "Two to three small factual errors" in severe_msg.content
    assert "no fake threat indicators" in severe_msg.content


def test_amend_prompt_garble_only_state_no_timebomb_passes_through() -> None:
    """state.timebomb_thresholds=(0, 0) (GARBLE mode): no amendment even
    when command_count is high."""
    strat = ModeAwareCounterDeceptionStrategy(_config(mode=CounterDeceptionMode.GARBLE))
    state = CounterDeceptionState(
        mode=CounterDeceptionMode.GARBLE,
        garble_paths=("/root/.ssh/id_rsa",),
        timebomb_thresholds=(0, 0),
    )
    messages = _messages()
    amended = strat.amend_prompt(messages=messages, command_count=999, state=state)
    assert [m.content for m in amended] == [m.content for m in messages]


def test_amend_prompt_does_not_mutate_input_list() -> None:
    """The input messages list must not be mutated; callers re-use it."""
    strat = ModeAwareCounterDeceptionStrategy(_config())
    state = CounterDeceptionState(
        mode=CounterDeceptionMode.TIMEBOMB,
        timebomb_thresholds=(6, 16),
    )
    messages = _messages()
    original_len = len(messages)
    _ = strat.amend_prompt(messages=messages, command_count=20, state=state)
    assert len(messages) == original_len
