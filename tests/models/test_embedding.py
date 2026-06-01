"""Tests for :class:`anglerfish.models.embedding.SessionEmbedding`.

Co-locates coverage of the model's one logic branch - the
dimension-vs-len(vector) cross-check - with the model (audit review M13);
it was previously exercised only incidentally via the intel suite.
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

import pytest
from pydantic import ValidationError

from anglerfish.models.embedding import SessionEmbedding

_AT = datetime(2026, 5, 28, 12, 0, tzinfo=UTC)


def test_embedding_dimension_matching_vector_length_is_accepted() -> None:
    vec = tuple(0.01 * i for i in range(64))
    emb = SessionEmbedding(
        session_id=uuid4(),
        vector=vec,
        dimension=64,
        model="embed-test",
        generated_at=_AT,
    )
    assert emb.dimension == len(emb.vector) == 64


def test_embedding_dimension_mismatch_is_rejected() -> None:
    """dimension != len(vector) raises rather than silently coercing."""
    vec = tuple(0.01 for _ in range(64))
    with pytest.raises(ValidationError):
        SessionEmbedding(
            session_id=uuid4(),
            vector=vec,
            dimension=128,
            model="embed-test",
            generated_at=_AT,
        )
