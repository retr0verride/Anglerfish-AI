"""Shared data model for per-session behavioural embedding vectors.

Stage 8 generates these via the deep-tier embed model after a
session closes (or short-circuits to ``None`` for sessions below
the min-commands threshold). The bridge persists each
:class:`SessionEmbedding` through the audit log; the dashboard's
tailer reads the audit event and writes the vector into the
session store.

Kept in :mod:`anglerfish.models` (alongside
:class:`IntentSummary` and :class:`ThreatAssessment`) so dashboard
reads, audit-tailer writes, and the generator's own boundary all
reference the same type without circular imports back into the
intel package.
"""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

__all__ = ["SessionEmbedding"]


class SessionEmbedding(BaseModel):
    """Persisted per-session embedding vector + provenance.

    ``vector`` is the immutable tuple of floats returned by
    :meth:`anglerfish.llm.LLMClient.embed`. ``dimension`` must
    equal ``len(vector)`` (cross-checked in the validator);
    storing both lets the persistence layer reject row reads
    whose blob has been truncated or corrupted.

    ``model`` is the embed model tag that produced the vector.
    The similarity-query path filters on this column so cross-
    model comparisons (which would compare vectors in different
    spaces) are silently excluded.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    session_id: UUID
    vector: tuple[float, ...] = Field(min_length=64, max_length=4096)
    dimension: int = Field(ge=64, le=4096)
    model: str = Field(min_length=1, max_length=128)
    generated_at: datetime

    def model_post_init(self, _context: object) -> None:
        # Pydantic v2 frozen=True still allows this assertion-free
        # post-init check; raise rather than coerce so callers
        # cannot mismatch the two fields.
        if self.dimension != len(self.vector):
            raise ValueError(
                f"SessionEmbedding.dimension={self.dimension} does not match "
                f"len(vector)={len(self.vector)}",
            )
