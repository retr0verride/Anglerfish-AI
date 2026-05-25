"""LLM-layer exception hierarchy.

Stage 5 moved the Ollama-specific error types here from
``anglerfish.bridge.errors`` so :mod:`anglerfish.llm.client` does
not have to import from the bridge package (which would re-enter
the bridge package init via its public re-exports).

``anglerfish.bridge.errors`` re-exports both names so existing
``from anglerfish.bridge.errors import OllamaUnavailableError``
call sites keep working. ``BridgeError`` stays in bridge.errors
because it covers more than the LLM path (rate-limit, injection,
output-filter errors live there too).
"""

from __future__ import annotations

__all__ = [
    "LLMError",
    "OllamaResponseError",
    "OllamaUnavailableError",
    "StructuredOutputError",
]


class LLMError(Exception):
    """Base for LLM-layer failures.

    ``BridgeError`` in ``anglerfish.bridge.errors`` inherits from
    this so a ``except BridgeError`` clause continues to catch
    LLM failures the bridge surfaces. New code that only cares
    about LLM failures catches :class:`LLMError`.
    """


class OllamaUnavailableError(LLMError):
    """Network-level failure or 5xx response from the Ollama endpoint."""


class OllamaResponseError(LLMError):
    """4xx response or structurally invalid response body."""


class StructuredOutputError(LLMError):
    """The LLM failed to produce schema-compliant output within the retry budget.

    Raised by :meth:`LLMClient.structured_chat` after the configured
    ``max_retries`` attempts have all returned either non-JSON text
    or a JSON object that fails the requested Pydantic schema.
    """
