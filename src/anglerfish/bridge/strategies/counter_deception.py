"""Counter-deception strategies (Stage 12).

Counter-deception lives next to the existing time-wasting strategies
because both operate on the same per-command call shape, but it does
NOT share a base class with :class:`WastingStrategyBase` - the
contract is different enough (different hook surface, different
state lifecycle) that a shared abstract base would force fake choices.

Stage 12 ships a single concrete implementation,
:class:`ModeAwareCounterDeceptionStrategy`, that interprets the
configured :class:`CounterDeceptionMode` enum and returns a
:class:`CounterDeceptionState` per session. The
:class:`CounterDeceptionStrategyBase` ABC reserves the extension point
for v1.1+ alternatives (DNS-poisoning strategies, persona-specific
strategies) without forcing multiple near-empty stub classes today.

See ``docs/design/STAGE_12_counter_deception.md`` for the full design.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import TYPE_CHECKING
from uuid import UUID

from anglerfish.config.models import CounterDeceptionMode
from anglerfish.llm.client import ChatMessage

if TYPE_CHECKING:
    from anglerfish.config.models import CounterDeceptionConfig
    from anglerfish.models.threat import ThreatAssessment

__all__ = [
    "CounterDeceptionState",
    "CounterDeceptionStrategyBase",
    "ModeAwareCounterDeceptionStrategy",
]


@dataclass(frozen=True)
class CounterDeceptionState:
    """Per-session counter-deception configuration.

    Carried on ``AIBridgeService._counter_deception_state`` and shipped
    to the lure via ``SessionStartResponse.counter_deception_garble_paths``
    at session-open (slice 12.2 wires the bridge state; slice 12.3
    wires the lure consumer). The time-bomb thresholds stay bridge-
    side; the lure has no need for them.

    ``timebomb_thresholds=(0, 0)`` disables time-bomb regardless of
    ``mode`` so ``GARBLE`` mode can carry an empty thresholds tuple
    without a separate "time-bomb on/off" boolean.
    """

    mode: CounterDeceptionMode
    garble_paths: tuple[str, ...] = ()
    timebomb_thresholds: tuple[int, int] = (0, 0)


class CounterDeceptionStrategyBase(ABC):
    """Per-session prompt + lure-overlay shaping interface."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Stable identifier for the strategy (audit-log + debug)."""

    @abstractmethod
    def state_for_session(
        self,
        *,
        threat: ThreatAssessment | None,
        session_id: UUID,
    ) -> CounterDeceptionState | None:
        """Resolve a per-session config, or None to skip engagement.

        Slice 12.2 calls this from
        ``AIBridgeService.engage_counter_deception`` when
        ``settings.counter_deception.enabled`` AND the threat score
        crosses ``engagement_threshold``. Returning None means the
        strategy declines to engage this session (the global flag
        is on but this session does not qualify).
        """

    @abstractmethod
    def amend_prompt(
        self,
        *,
        messages: list[ChatMessage],
        command_count: int,
        state: CounterDeceptionState,
    ) -> list[ChatMessage]:
        """Return a modified message list.

        Slice 12.2 calls this per command from
        ``AIBridgeService.amend_prompt_for_session`` after the regular
        prompt build. Strategies that do not use the prompt-shaping
        hook return ``messages`` unchanged.
        """


_MILD_INSTRUCTION = (
    "When describing file or process state, introduce ONE small factual "
    "error per response: wrong PID, slightly wrong file size in bytes, "
    "wrong port number off by 1-10, or a plausibly-named-but-nonexistent "
    "path. Do not announce the error. Do not introduce errors in security-"
    "relevant text the operator would notice in audit logs (no fake "
    "credentials, no fake IP addresses outside RFC 1918, no fake CVE numbers)."
)


_SEVERE_INSTRUCTION = (
    "Increase the error rate. Two to three small factual errors per response. "
    "Confidently assert the wrong values. The same rules apply: no security-"
    "sensitive errors, no fake threat indicators."
)


class ModeAwareCounterDeceptionStrategy(CounterDeceptionStrategyBase):
    """v1 concrete strategy.

    Behaves per the configured :class:`CounterDeceptionMode`:

    * ``OFF``: ``state_for_session`` returns ``None`` (no engagement).
    * ``GARBLE``: state with ``garble_paths`` populated;
      ``timebomb_thresholds=(0, 0)``.
    * ``TIMEBOMB``: state with empty ``garble_paths``;
      ``timebomb_thresholds`` from config.
    * ``BOTH``: ``garble_paths`` + ``timebomb_thresholds`` both populated.
    """

    def __init__(self, config: CounterDeceptionConfig) -> None:
        self._config = config

    @property
    def name(self) -> str:
        return "mode-aware"

    def state_for_session(
        self,
        *,
        threat: ThreatAssessment | None,
        session_id: UUID,
    ) -> CounterDeceptionState | None:
        del threat, session_id  # advisory; this strategy reads only config
        mode = self._config.mode
        if mode is CounterDeceptionMode.OFF:
            return None
        garble_paths: tuple[str, ...] = ()
        timebomb_thresholds: tuple[int, int] = (0, 0)
        if mode in (CounterDeceptionMode.GARBLE, CounterDeceptionMode.BOTH):
            garble_paths = self._config.garble_paths
        if mode in (CounterDeceptionMode.TIMEBOMB, CounterDeceptionMode.BOTH):
            timebomb_thresholds = (
                self._config.timebomb_cold_to_mild,
                self._config.timebomb_mild_to_severe,
            )
        return CounterDeceptionState(
            mode=mode,
            garble_paths=garble_paths,
            timebomb_thresholds=timebomb_thresholds,
        )

    def amend_prompt(
        self,
        *,
        messages: list[ChatMessage],
        command_count: int,
        state: CounterDeceptionState,
    ) -> list[ChatMessage]:
        cold_to_mild, mild_to_severe = state.timebomb_thresholds
        if cold_to_mild == 0 and mild_to_severe == 0:
            return list(messages)
        if command_count < cold_to_mild:
            return list(messages)
        amended = list(messages)
        amended.append(ChatMessage(role="system", content=_MILD_INSTRUCTION))
        if command_count >= mild_to_severe:
            amended.append(ChatMessage(role="system", content=_SEVERE_INSTRUCTION))
        return amended
