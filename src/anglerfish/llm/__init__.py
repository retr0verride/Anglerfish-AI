"""Single LLM boundary for Anglerfish AI.

Stage 5 replaces the pre-existing
:class:`anglerfish.bridge.client.OllamaClient` with this package. The
old import path still works (it re-exports from here) for one
release cycle so call sites can migrate without churning every
test in lockstep.

Public surface:

* :class:`LLMClient` - async client around Ollama. Exposes
  ``chat()`` (buffered), ``stream_chat()`` (NDJSON streaming),
  ``structured_chat()`` (Pydantic-schema-validated with
  retry-on-malformed), ``embed()`` (vector for a text), and
  ``warm()`` (no-op call with ``keep_alive=-1`` to pin the model
  in Ollama's memory). All take an optional :class:`TokenBudget`.
* :class:`LLMRole` - three tiers: ``FAST`` for per-command shell
  responses, ``DEEP`` for Stage 7+ intent extraction, ``EMBED``
  for Stage 8 behavioural clustering.
* :class:`ChatMessage` - one Ollama chat-protocol message.
* :class:`ChatResult` / :class:`ChatChunk` / :class:`TokenUsage` -
  parsed responses (buffered, streamed, and the usage block).
* :class:`TokenBudget` + :class:`BudgetExhaustedError` - per-
  session token cap with one bucket per role.
* :class:`WarmPool` + :class:`WarmStatus` - background warm-up
  task that keeps every configured role resident.
* Errors: :class:`anglerfish.llm.errors.LLMError` base plus
  :class:`OllamaUnavailableError` (network / 5xx),
  :class:`OllamaResponseError` (4xx / malformed body), and
  :class:`StructuredOutputError` (schema retries exhausted).
"""

from __future__ import annotations

from anglerfish.llm.budget import BudgetExhaustedError, TokenBudget
from anglerfish.llm.client import ChatChunk, ChatMessage, ChatResult, LLMClient, TokenUsage
from anglerfish.llm.errors import StructuredOutputError
from anglerfish.llm.roles import LLMRole
from anglerfish.llm.warmup import WarmPool, WarmStatus

__all__ = [
    "BudgetExhaustedError",
    "ChatChunk",
    "ChatMessage",
    "ChatResult",
    "LLMClient",
    "LLMRole",
    "StructuredOutputError",
    "TokenBudget",
    "TokenUsage",
    "WarmPool",
    "WarmStatus",
]
