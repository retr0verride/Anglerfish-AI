"""Per-session token budget for the LLM layer.

A pathological attacker can hold one SSH connection open for hours
and emit a fresh command every few seconds. Each command is one LLM
round trip; without a cap, the deep tier becomes a denial-of-service
vector for the dashboard (slow GPU work serialised through the
warm-pool) and an inference-cost sink on shared-host deployments.

:class:`TokenBudget` is a mutable per-role counter. Constructed once
per attacker session, passed through :meth:`LLMClient.chat` /
:meth:`LLMClient.stream_chat`, and decremented by the actual usage
Ollama reports on the response. When the remaining budget for a
role goes to zero, the next call raises
:class:`BudgetExhaustedError` *before* hitting Ollama; the bridge
service catches that and degrades to a scripted fallback so the
attacker sees an indistinguishable response.

Budgets are advisory at the HTTP layer (the operator-facing
dashboard surfaces consumed/remaining) and load-bearing at the
inference layer (the LLMClient is what enforces them).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from anglerfish.llm.errors import LLMError
from anglerfish.llm.roles import LLMRole

__all__ = ["BudgetExhaustedError", "TokenBudget"]


class BudgetExhaustedError(LLMError):
    """The configured token cap for the requested role is consumed."""


@dataclass
class TokenBudget:
    """Per-role token cap and running consumption counter.

    One instance per attacker session. ``cap_<role>`` is the hard
    ceiling; ``consumed_<role>`` is the running total Ollama reported
    across all calls. When ``consumed >= cap`` the role refuses
    further calls.

    Setting a cap to zero disables that role for the session; the
    LLMClient raises :class:`BudgetExhaustedError` on the next call.
    A non-positive cap is rejected at construction.
    """

    fast_token_cap: int = 50_000
    deep_token_cap: int = 20_000
    consumed_fast: int = field(default=0)
    consumed_deep: int = field(default=0)

    def __post_init__(self) -> None:
        if self.fast_token_cap < 0:
            raise ValueError(
                f"TokenBudget.fast_token_cap must be >= 0, got {self.fast_token_cap}",
            )
        if self.deep_token_cap < 0:
            raise ValueError(
                f"TokenBudget.deep_token_cap must be >= 0, got {self.deep_token_cap}",
            )

    def remaining(self, role: LLMRole) -> int:
        """Return remaining tokens for ``role`` (never negative)."""
        cap, consumed = self._cap_and_consumed(role)
        return max(0, cap - consumed)

    def check(self, role: LLMRole) -> None:
        """Raise :class:`BudgetExhaustedError` if ``role`` has no budget left."""
        if self.remaining(role) <= 0:
            raise BudgetExhaustedError(
                f"token budget for role={role.value} exhausted "
                f"(cap={self._cap(role)}, consumed={self._consumed(role)})",
            )

    def consume(self, role: LLMRole, tokens: int) -> None:
        """Add ``tokens`` to ``role``'s running consumption."""
        if tokens < 0:
            raise ValueError(f"tokens to consume must be >= 0, got {tokens}")
        if role is LLMRole.FAST:
            self.consumed_fast += tokens
        elif role is LLMRole.DEEP:
            self.consumed_deep += tokens
        else:  # pragma: no cover - covered when Stage 8 adds EMBED
            raise ValueError(f"unknown role: {role!r}")

    def as_dict(self) -> dict[str, dict[str, int]]:
        """Return a JSON-serialisable per-role consumed/remaining/cap snapshot."""
        return {
            "fast": {
                "cap": self.fast_token_cap,
                "consumed": self.consumed_fast,
                "remaining": self.remaining(LLMRole.FAST),
            },
            "deep": {
                "cap": self.deep_token_cap,
                "consumed": self.consumed_deep,
                "remaining": self.remaining(LLMRole.DEEP),
            },
        }

    def _cap(self, role: LLMRole) -> int:
        return self._cap_and_consumed(role)[0]

    def _consumed(self, role: LLMRole) -> int:
        return self._cap_and_consumed(role)[1]

    def _cap_and_consumed(self, role: LLMRole) -> tuple[int, int]:
        if role is LLMRole.FAST:
            return self.fast_token_cap, self.consumed_fast
        if role is LLMRole.DEEP:
            return self.deep_token_cap, self.consumed_deep
        raise ValueError(f"unknown role: {role!r}")
