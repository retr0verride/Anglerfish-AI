"""Logical LLM roles.

Two tiers in Stage 5: ``FAST`` handles every attacker command;
``DEEP`` is reserved for Stage 7+ paths that need stronger
reasoning (intent extraction, session summarisation). Each role
maps to a distinct Ollama model tag configured under
:class:`anglerfish.config.models.OllamaConfig`.

Stage 8 adds ``EMBED`` for behavioural clustering when the
clustering consumer lands and can validate the embedding-vector
shape.
"""

from __future__ import annotations

from enum import StrEnum

__all__ = ["LLMRole"]


class LLMRole(StrEnum):
    FAST = "fast"
    DEEP = "deep"
