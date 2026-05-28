"""Shared data model for operator-driven counter-deception pins (Stage 12).

The dashboard's ``POST /api/counter_deception/pin`` route writes one of
these per pinned source IP; the bridge reads them via
:class:`SessionStoreReader.get_counter_deception_pin` at session-open
and applies the pinned :class:`CounterDeceptionMode` before the
threat-driven engagement path runs. A pin overrides the threat
threshold: ``mode='off'`` whitelists an IP (no counter-deception even
above the threshold), any other mode force-engages with that mode.

Kept in :mod:`anglerfish.models` (alongside the other cross-process
shared types) so the dashboard write path, the bridge read path, and
the SessionStore CRUD all reference the same shape.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from anglerfish.config.models import CounterDeceptionMode

__all__ = ["CounterDeceptionPin"]


class CounterDeceptionPin(BaseModel):
    """One operator-pinned source_ip -> CounterDeceptionMode binding."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    source_ip: str = Field(min_length=1, max_length=64)
    mode: CounterDeceptionMode = Field(
        description=(
            "Forced counter-deception mode for this source IP. 'off' is a "
            "whitelist (suppresses engagement even above the threat "
            "threshold); garble / timebomb / both force-engage with that "
            "mode regardless of score."
        ),
    )
    created_at: datetime
    created_by: str = Field(
        min_length=1,
        max_length=128,
        description=(
            "Operator user (from the dashboard auth session) that issued "
            "the pin. Audit trail; not load-bearing for engagement."
        ),
    )
