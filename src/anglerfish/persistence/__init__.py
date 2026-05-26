"""Detection + classification of attacker persistence-installation attempts.

The package is the Stage 10 bridge-side machinery. Slice 10.1
ships the regex catalog + the classifier orchestration with a
regex-only hot path. Slice 10.3 wires the LLM fast-tier pass for
ambiguous (regex-silent) write-shape commands.

The package depends only on stdlib + anglerfish.models +
anglerfish.llm (so classifier construction in tests can pass an
LLMClient or None freely).
"""

from __future__ import annotations

from anglerfish.persistence.classifier import PersistenceClassifier
from anglerfish.persistence.patterns import extract_event

__all__ = ["PersistenceClassifier", "extract_event"]
