"""Tests for :mod:`anglerfish.models.threat`."""

from __future__ import annotations

from uuid import uuid4

import pytest
from pydantic import ValidationError

from anglerfish.models.threat import ThreatAssessment, ThreatTechnique


def test_threat_technique_constructs() -> None:
    t = ThreatTechnique(id="T1059", name="Command Interpreter", matches=("bash",))
    assert t.id == "T1059"


def test_threat_technique_frozen() -> None:
    t = ThreatTechnique(id="T1", name="x")
    with pytest.raises(ValidationError):
        t.id = "T2"  # type: ignore[misc]


def test_threat_assessment_score_bounded() -> None:
    with pytest.raises(ValidationError):
        ThreatAssessment(session_id=uuid4(), score=-1)
    with pytest.raises(ValidationError):
        ThreatAssessment(session_id=uuid4(), score=101)


def test_threat_assessment_defaults() -> None:
    a = ThreatAssessment(session_id=uuid4(), score=50)
    assert a.techniques == ()
    assert a.persistence_attempted is False
    assert a.notes == ()
