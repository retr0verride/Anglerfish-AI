"""LLM-driven intelligence layer on top of captured sessions.

Stage 7 ships :class:`IntentExtractor`, the end-of-session
structured-summary producer. Stage 8 will land
``embeddings.py`` here for behavioural clustering.

Public surface:

* :class:`IntentExtractor` - construct from an
  :class:`anglerfish.llm.LLMClient`; ``extract()`` consumes a
  :class:`anglerfish.models.SessionSnapshot` (plus an optional
  rule-based :class:`anglerfish.models.ThreatAssessment` for
  context) and returns a populated
  :class:`anglerfish.models.IntentSummary`.

Errors:

* :class:`IntentExtractionError` - base class. Slice 7.1 raises
  on no underlying LLM failure path - those propagate through
  unchanged. Subclasses arrive when there are real semantic
  failure modes to distinguish (Stage 7.2 + later).
"""

from __future__ import annotations

from anglerfish.intel.intent import (
    IntentExtractionError,
    IntentExtractor,
)

__all__ = ["IntentExtractionError", "IntentExtractor"]
