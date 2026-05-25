"""Exception hierarchy for the AI bridge.

All bridge-level errors derive from :class:`BridgeError`. Callers that
want generic protection against bridge failures catch
:class:`BridgeError`; callers that want to distinguish causes catch a
more specific subclass.

The bridge service itself catches these internally and degrades to
fallback responses so that Cowrie never sees an exception.

Stage 5 moved :class:`OllamaUnavailableError` and
:class:`OllamaResponseError` to :mod:`anglerfish.llm.errors`; they
are re-exported here so existing ``from anglerfish.bridge.errors
import OllamaUnavailableError`` call sites keep working. The
:class:`BridgeError` base now multiply-inherits :class:`LLMError`
so ``except BridgeError`` still catches LLM failures.
"""

from __future__ import annotations

from anglerfish.llm.errors import LLMError, OllamaResponseError, OllamaUnavailableError

__all__ = [
    "BridgeError",
    "GlobalQueueTimeoutError",
    "InjectionDetectedError",
    "OllamaResponseError",
    "OllamaUnavailableError",
    "OutputFilterFiredError",
    "SessionRateLimitedError",
]


class BridgeError(LLMError):
    """Base class for all bridge errors.

    Inherits from :class:`anglerfish.llm.errors.LLMError` so callers
    that catch ``BridgeError`` continue to catch LLM transport and
    response errors after the Stage 5 split.
    """


class SessionRateLimitedError(BridgeError):
    """One attacker session has exceeded its per-minute command budget."""


class GlobalQueueTimeoutError(BridgeError):
    """Global Ollama concurrency slot could not be acquired in time."""


class InjectionDetectedError(BridgeError):
    """Attacker input matched a Stage 1 injection-scorer signature.

    Carries the firing :class:`~anglerfish.bridge.defense.DefenseVerdict`
    for audit-log enrichment. The bridge converts this into a fallback
    response so the attacker never learns defense fired.
    """


class OutputFilterFiredError(BridgeError):
    """LLM response matched a Stage 1 output-filter signature.

    Same handling as :class:`InjectionDetectedError`: caught by the
    bridge, replaced with a fallback response, audit-logged.
    """
