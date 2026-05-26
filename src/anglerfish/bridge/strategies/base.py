"""Base types for the bridge's time-wasting strategies.

:class:`WastingStrategyBase` is the protocol every strategy
implements. The bridge service calls ``pre_command`` once before
the LLM request and ``between_chunks`` after each AI chunk in the
streaming response; the strategy's return values tell the bridge
what to emit and how long to pace.

:class:`StrategyContext` carries the per-command information a
strategy needs to decide (session id, attacker command text,
wasted-ms-so-far for the session, bridge config snapshot) without
reaching into bridge internals. :class:`StrategyPreEffect`
captures the pre-command output: an optional pre-message, the
delay before it, and the delay before the LLM call begins.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from uuid import UUID

from anglerfish.config.models import BridgeConfig
from anglerfish.models.session import BridgeChunk

__all__ = ["StrategyContext", "StrategyPreEffect", "WastingStrategyBase"]


@dataclass(frozen=True)
class StrategyContext:
    """Per-command information passed to the strategy.

    ``wasted_ms_so_far`` is the running per-session total of time
    the strategy has added. Strategies consult it to honour the
    session cap (slice 6.5 ships the cap; earlier slices pass 0).

    ``command_count`` is the 0-based index of this command within
    the session (0 for the first command, 1 for the second, ...).
    Strategies use it together with ``session_id`` to seed a
    deterministic PRNG so per-command randomness is reproducible
    across bridge restarts and pinnable in tests.

    ``last_clarification_command_count`` is the ``command_count``
    of the most recent clarification-injected command in this
    session, or ``None`` if none yet. The aggressive strategy uses
    it to enforce the one-clarification-per-chain rule: after
    injecting, never inject on the immediately-following command.
    """

    session_id: UUID
    command: str
    command_count: int
    wasted_ms_so_far: int
    bridge_config: BridgeConfig
    last_clarification_command_count: int | None = None


@dataclass(frozen=True)
class StrategyPreEffect:
    """What a strategy wants done before the LLM call.

    ``pre_message`` is written to the attacker terminal before the
    LLM response begins streaming; ``None`` skips the message.
    ``pre_message_delay_ms`` is the delay before the message is
    emitted (zero if no message). ``pre_delay_ms`` is the delay
    after the message (or after pre_command returns when there is
    no message) and before the LLM request is sent.

    ``inject_clarification`` is the aggressive-strategy signal
    (slice 6.4) that this command should produce a "did you mean
    X or Y?" clarification question instead of executing. The
    bridge swaps in the clarification prompt template, ships the
    AI response as the reply, and records the session's
    last-clarification command_count so the next command does not
    also inject.
    """

    pre_message: str | None = None
    pre_message_delay_ms: int = 0
    pre_delay_ms: int = 0
    inject_clarification: bool = False

    @property
    def total_added_ms(self) -> int:
        """Total milliseconds this pre-effect contributes to the session cap."""
        return self.pre_message_delay_ms + self.pre_delay_ms


class WastingStrategyBase(ABC):
    """Abstract base for per-command time-wasting strategies."""

    @property
    @abstractmethod
    def name(self) -> str:
        """The strategy's stable identifier (``"off"`` / ``"light"`` / ...)."""

    @abstractmethod
    async def pre_command(self, ctx: StrategyContext) -> StrategyPreEffect:
        """Compute the pre-LLM effect for ``ctx``."""

    @abstractmethod
    async def between_chunks(
        self,
        ctx: StrategyContext,
        chunk: BridgeChunk,
    ) -> float:
        """Return the inter-chunk sleep in seconds (``0.0`` for no delay)."""
