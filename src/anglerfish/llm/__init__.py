"""Single LLM boundary for Anglerfish AI.

Stage 5 replaces the pre-existing
:class:`anglerfish.bridge.client.OllamaClient` with this package. The
old import path still works (it re-exports from here) for one
release cycle so call sites can migrate without churning every
test in lockstep.

Public surface:

* :class:`LLMClient` - async chat client; ``chat()`` returns a
  :class:`ChatResult` carrying both content and Ollama-reported
  token usage. Streaming, structured output, and per-session
  budgets land in later Stage 5 slices.
* :class:`LLMRole` - ``FAST`` and ``DEEP``. The fast tier handles
  every command; deep is reserved for Stage 7+ summarisation
  paths. Embed is deferred to Stage 8 (when its consumer lands).
* :class:`ChatMessage` - one Ollama chat-protocol message.
* :class:`ChatResult` / :class:`TokenUsage` - parsed response.
* Error types mirror the original module:
  :class:`anglerfish.bridge.errors.OllamaUnavailableError` and
  :class:`OllamaResponseError`.
"""

from __future__ import annotations

from anglerfish.llm.client import ChatMessage, ChatResult, LLMClient, TokenUsage
from anglerfish.llm.roles import LLMRole

__all__ = [
    "ChatMessage",
    "ChatResult",
    "LLMClient",
    "LLMRole",
    "TokenUsage",
]
