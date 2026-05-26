"""LLM-driven intelligence layer on top of captured sessions.

Two end-of-session producers live here:

* :class:`IntentExtractor` (Stage 7) - structured natural-language
  intent summary via :meth:`LLMClient.structured_chat`.
* :class:`EmbeddingGenerator` (Stage 8) - per-session behavioural
  embedding vector via :meth:`LLMClient.embed` for the clustering
  + re-identification surface.

Public surface:

* :class:`IntentExtractor` - construct from an
  :class:`anglerfish.llm.LLMClient`; ``extract()`` consumes a
  :class:`anglerfish.models.SessionSnapshot` (plus an optional
  rule-based :class:`anglerfish.models.ThreatAssessment` for
  context) and returns a populated
  :class:`anglerfish.models.IntentSummary`.
* :class:`EmbeddingGenerator` - construct from an
  :class:`anglerfish.llm.LLMClient`; ``generate()`` consumes a
  :class:`anglerfish.models.SessionSnapshot` and returns either a
  populated :class:`anglerfish.models.SessionEmbedding` or
  :data:`None` when the session is below the configured
  min-commands threshold.

Errors:

* :class:`IntentExtractionError` - base class for intent-side
  failures. Underlying LLM-layer failures propagate unchanged.
* :class:`EmbeddingExtractionError` - base class for embedding-
  side failures with the same propagation contract.
"""

from __future__ import annotations

from anglerfish.intel.embeddings import (
    EmbeddingExtractionError,
    EmbeddingGenerator,
)
from anglerfish.intel.intent import (
    IntentExtractionError,
    IntentExtractor,
)

__all__ = [
    "EmbeddingExtractionError",
    "EmbeddingGenerator",
    "IntentExtractionError",
    "IntentExtractor",
]
