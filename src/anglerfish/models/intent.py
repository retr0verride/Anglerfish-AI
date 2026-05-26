"""Shared data model for LLM-generated session intent summaries.

Stage 7 produces these via the deep-tier LLM after a session
closes. The bridge persists each :class:`IntentSummary` through
the audit log; the dashboard's tailer (Stage 4.2) reads the audit
event and writes the record into the session store.

Kept in :mod:`anglerfish.models` (alongside
:class:`ThreatAssessment`) so dashboard reads, audit-tailer
writes, and the extractor's own boundary all reference the same
type without circular imports back into the intel package.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

__all__ = ["IntentSummary"]


ActorProfile = Literal[
    "opportunistic",
    "automated",
    "targeted",
    "exploratory",
]
"""Categorical guess at the attacker's posture.

* ``opportunistic`` - generic scanners, broad brute force
* ``automated`` - IoT-style botnets, scripted exploit chains
* ``targeted`` - appears to know the deployment
* ``exploratory`` - human-driven recon with no clear goal
"""


IntentConfidence = Literal["low", "medium", "high"]
"""LLM's self-reported confidence in the produced summary.

The Stage 7 extractor also emits ``confidence="low"`` on the
placeholder path for sessions below the min-commands threshold;
callers distinguish placeholder from low-confidence-real by
checking whether ``summary`` is the fixed placeholder string.
"""


class IntentSummary(BaseModel):
    """LLM-generated end-of-session structured summary."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    session_id: UUID
    actor_profile: ActorProfile
    intent: str = Field(min_length=1, max_length=400)
    why: str = Field(min_length=1, max_length=800)
    matched_techniques: tuple[str, ...] = Field(default=(), max_length=50)
    confidence: IntentConfidence
    summary: str = Field(min_length=1, max_length=2000)
    extracted_at: datetime
