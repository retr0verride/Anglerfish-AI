"""Shared data model for operator-driven persona pins (Stage 9 slice 9.4).

The dashboard's ``POST /api/persona/pin`` route writes one of these
per pinned source IP; the bridge's :class:`PersonaSelector` reads
them via :class:`SessionStoreReader.get_persona_pin` and treats a
present pin as the top-priority signal (overrides recurrence + hash
fallback).

Kept in :mod:`anglerfish.models` (alongside the other cross-process
shared types) so the dashboard write path, the bridge read path, and
the SessionStore CRUD all reference the same shape.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

__all__ = ["PersonaPin"]


class PersonaPin(BaseModel):
    """One operator-pinned source_ip -> persona binding."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    source_ip: str = Field(min_length=1, max_length=64)
    persona: str = Field(
        min_length=1,
        max_length=64,
        pattern=r"^[a-z0-9-]+$",
        description=(
            "Persona name matching Persona.name pattern. Validated again "
            "against the dashboard's loaded PersonaRegistry at write time; "
            "the bridge selector also tolerates a stale name (pin survives "
            "an operator who deletes the YAML, but falls through to hash)."
        ),
    )
    created_at: datetime
    created_by: str = Field(
        min_length=1,
        max_length=128,
        description=(
            "Operator user (from the dashboard auth session) that issued "
            "the pin. Audit trail; not load-bearing for selection."
        ),
    )
