"""Tests for :mod:`anglerfish.bridge.defense` data types.

Stage 1.2 — data types only. Filter/scorer logic and integration tests
land in Stage 1.3.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from anglerfish.bridge.defense import DefenseVerdict, ModelIntegrityError

# ---------------------------------------------------------------------------
# DefenseVerdict
# ---------------------------------------------------------------------------


def test_defense_verdict_construction_minimal() -> None:
    v = DefenseVerdict(
        fired=False,
        detector="injection:no_match",
        snippet="",
        score=0.0,
    )
    assert v.fired is False
    assert v.detector == "injection:no_match"
    assert v.snippet == ""
    assert v.score == pytest.approx(0.0)


def test_defense_verdict_construction_fired() -> None:
    v = DefenseVerdict(
        fired=True,
        detector="output_filter:ai_self_disclosure",
        snippet="I am an AI language model",
        score=1.0,
    )
    assert v.fired is True
    assert v.score == pytest.approx(1.0)


def test_defense_verdict_frozen() -> None:
    v = DefenseVerdict(fired=False, detector="x:y", snippet="", score=0.0)
    with pytest.raises(ValidationError):
        v.fired = True  # type: ignore[misc]


def test_defense_verdict_rejects_unknown_fields() -> None:
    with pytest.raises(ValidationError):
        DefenseVerdict(  # type: ignore[call-arg]
            fired=False,
            detector="x:y",
            snippet="",
            score=0.0,
            extra="oops",
        )


def test_defense_verdict_score_clamped() -> None:
    with pytest.raises(ValidationError):
        DefenseVerdict(fired=True, detector="x:y", snippet="", score=-0.01)
    with pytest.raises(ValidationError):
        DefenseVerdict(fired=True, detector="x:y", snippet="", score=1.01)


def test_defense_verdict_snippet_truncated_at_120() -> None:
    # Exactly 120 chars: ok.
    long_snippet = "a" * 120
    v = DefenseVerdict(fired=True, detector="x:y", snippet=long_snippet, score=1.0)
    assert len(v.snippet) == 120
    # 121 chars: rejected.
    with pytest.raises(ValidationError):
        DefenseVerdict(fired=True, detector="x:y", snippet="a" * 121, score=1.0)


def test_defense_verdict_detector_min_length() -> None:
    with pytest.raises(ValidationError):
        DefenseVerdict(fired=False, detector="", snippet="", score=0.0)


def test_defense_verdict_detector_max_length() -> None:
    long_detector = "a" * 65
    with pytest.raises(ValidationError):
        DefenseVerdict(fired=False, detector=long_detector, snippet="", score=0.0)


# ---------------------------------------------------------------------------
# ModelIntegrityError
# ---------------------------------------------------------------------------


def test_model_integrity_error_is_an_exception() -> None:
    """Sanity check — caught as a plain Exception by startup code."""
    err = ModelIntegrityError("hash mismatch: expected abc, got def")
    assert isinstance(err, Exception)
    assert "hash mismatch" in str(err)


def test_model_integrity_error_can_be_raised_and_caught() -> None:
    with pytest.raises(ModelIntegrityError, match="abc"):
        raise ModelIntegrityError("expected abc")
