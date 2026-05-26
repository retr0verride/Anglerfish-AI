"""Logical LLM roles.

Three tiers:

* ``FAST`` (Stage 5) handles every attacker command - low
  latency, low cost per call, runs on a chat-capable small
  model (default ``qwen3:14b``).
* ``DEEP`` (Stage 5) is reserved for Stage 7+ paths that need
  stronger reasoning (intent extraction, session summarisation).
  Larger chat model, slower, not called per-command.
* ``EMBED`` (Stage 8) generates session-history embedding
  vectors for behavioural clustering. Embedding model (default
  ``nomic-embed-text``), not chat-capable; the LLMClient calls
  ``/api/embeddings`` for this role rather than ``/api/chat``.

Each role maps to a distinct Ollama model tag configured under
:class:`anglerfish.config.models.OllamaConfig`.
"""

from __future__ import annotations

from enum import StrEnum

__all__ = ["LLMRole"]


class LLMRole(StrEnum):
    """Identifier for an LLM tier; see the module docstring for the mapping."""

    FAST = "fast"
    DEEP = "deep"
    EMBED = "embed"
