"""Shared data models for the threat engine."""

from __future__ import annotations

from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

__all__ = ["ThreatAssessment", "ThreatTechnique"]


class ThreatTechnique(BaseModel):
    """One MITRE ATT&CK technique observed in a session."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str = Field(..., min_length=1, max_length=32)
    name: str = Field(..., min_length=1, max_length=128)
    matches: tuple[str, ...] = Field(default=())


class ThreatAssessment(BaseModel):
    """Computed threat assessment for a single attacker session."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    session_id: UUID
    score: int = Field(ge=0, le=100)
    techniques: tuple[ThreatTechnique, ...] = Field(default=())
    persistence_attempted: bool = False
    high_severity: bool = False
    notes: tuple[str, ...] = Field(default=())
