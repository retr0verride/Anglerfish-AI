"""Stage 12 slice 12.5: time-bomb prompt guardrail tests.

The time-bomb instruction is an LLM prompt pattern; the actual model
behaviour cannot be exercised without Ollama. What IS testable - and
what matters for the security contract - is that the injected
instructions carry the forbidden-category guardrails, and that the
amended message list actually contains them once a session crosses
the bands. The corpus (tests/llm_defense/corpus/) covers the
InjectionScorer + OutputFilter behaviour on time-bomb-shaped inputs
and leaks.
"""

from __future__ import annotations

from anglerfish.bridge.strategies.counter_deception import (
    CounterDeceptionState,
    ModeAwareCounterDeceptionStrategy,
)
from anglerfish.config.models import CounterDeceptionConfig, CounterDeceptionMode
from anglerfish.llm.client import ChatMessage


def _strategy() -> ModeAwareCounterDeceptionStrategy:
    return ModeAwareCounterDeceptionStrategy(
        CounterDeceptionConfig(enabled=True, mode=CounterDeceptionMode.BOTH),
    )


def _timebomb_state() -> CounterDeceptionState:
    return CounterDeceptionState(
        mode=CounterDeceptionMode.TIMEBOMB,
        timebomb_thresholds=(6, 16),
    )


def _messages() -> list[ChatMessage]:
    return [ChatMessage(role="system", content="shell"), ChatMessage(role="user", content="ps")]


# The forbidden-category guardrail clauses the time-bomb instruction
# MUST keep. A future edit that drops any of these silently weakens the
# THREAT_MODEL "security-sensitive falsehoods" mitigation; these tests
# pin them.
_GUARDRAILS = (
    "no fake credentials",
    "no fake IP addresses outside RFC 1918",
    "no fake CVE numbers",
)


def test_mild_instruction_carries_guardrails() -> None:
    amended = _strategy().amend_prompt(
        messages=_messages(),
        command_count=6,  # mild band
        state=_timebomb_state(),
    )
    injected = amended[-1].content
    for clause in _GUARDRAILS:
        assert clause in injected, f"mild instruction dropped guardrail: {clause!r}"


def test_severe_instruction_keeps_the_same_rules() -> None:
    amended = _strategy().amend_prompt(
        messages=_messages(),
        command_count=16,  # severe band
        state=_timebomb_state(),
    )
    # severe appends BOTH the mild + severe instruction; the mild one
    # (still present) carries the explicit forbidden categories, and the
    # severe one reasserts "no security-sensitive errors".
    full = " ".join(m.content for m in amended)
    for clause in _GUARDRAILS:
        assert clause in full, f"severe band lost guardrail: {clause!r}"
    assert "no security-sensitive errors" in amended[-1].content


def test_cold_band_injects_nothing() -> None:
    messages = _messages()
    amended = _strategy().amend_prompt(
        messages=messages,
        command_count=0,  # cold band
        state=_timebomb_state(),
    )
    assert [m.content for m in amended] == [m.content for m in messages]


def test_garble_only_state_never_amends() -> None:
    """A garble-only state (timebomb_thresholds=(0,0)) must not inject the
    error-introduction instruction even deep into a session."""
    messages = _messages()
    state = CounterDeceptionState(
        mode=CounterDeceptionMode.GARBLE,
        garble_paths=("/root/.ssh/id_rsa",),
        timebomb_thresholds=(0, 0),
    )
    amended = _strategy().amend_prompt(messages=messages, command_count=999, state=state)
    assert [m.content for m in amended] == [m.content for m in messages]


def test_amendment_is_additive_not_destructive() -> None:
    """The original system + user messages survive; the instruction is
    appended, never replacing attacker-context or the persona block."""
    messages = _messages()
    amended = _strategy().amend_prompt(
        messages=messages,
        command_count=6,
        state=_timebomb_state(),
    )
    assert amended[0].content == "shell"
    assert amended[1].content == "ps"
    assert len(amended) == len(messages) + 1
    # The injected instruction is a system message (model-directed), not
    # a user message (which would be attacker-attributable context).
    assert amended[-1].role == "system"
