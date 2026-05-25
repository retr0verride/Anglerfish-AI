"""Deprecated re-export of the LLM client from :mod:`anglerfish.llm`.

Stage 5 moved the canonical client to ``anglerfish.llm.LLMClient``;
this module survives for one release cycle so call sites and tests
can migrate without churning in lockstep. New code imports from
``anglerfish.llm`` directly.

Behaviour notes for callers who still import the old name:

* The class is now :class:`anglerfish.llm.LLMClient`; the
  ``OllamaClient`` name aliases to it here.
* ``chat()`` returns a :class:`anglerfish.llm.ChatResult` (content +
  token usage), not a bare ``str``. Call sites must unwrap via
  ``result.content`` - the old single-string return is gone in
  Stage 5 even via this alias.
"""

from __future__ import annotations

from anglerfish.llm.client import ChatMessage, ChatResult, LLMClient, TokenUsage

# Legacy alias; remove with the module after one release cycle.
OllamaClient = LLMClient

__all__ = ["ChatMessage", "ChatResult", "OllamaClient", "TokenUsage"]
