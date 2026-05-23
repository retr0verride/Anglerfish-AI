"""Exception hierarchy for the AI bridge.

All bridge-level errors derive from :class:`BridgeError`. Callers that
want generic protection against bridge failures catch
:class:`BridgeError`; callers that want to distinguish causes catch a
more specific subclass.

The bridge service itself catches these internally and degrades to
fallback responses so that Cowrie never sees an exception.
"""

from __future__ import annotations

__all__ = [
    "BridgeError",
    "GlobalQueueTimeoutError",
    "OllamaResponseError",
    "OllamaUnavailableError",
    "SessionRateLimitedError",
]


class BridgeError(Exception):
    """Base class for all bridge errors."""


class OllamaUnavailableError(BridgeError):
    """Network-level failure or 5xx response from the Ollama endpoint."""


class OllamaResponseError(BridgeError):
    """4xx response or structurally invalid response body."""


class SessionRateLimitedError(BridgeError):
    """One attacker session has exceeded its per-minute command budget."""


class GlobalQueueTimeoutError(BridgeError):
    """Global Ollama concurrency slot could not be acquired in time."""
