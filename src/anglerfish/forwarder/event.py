"""Forwarder event envelopes.

The forwarder is intentionally generic: it accepts a :class:`ForwarderEvent`
containing an arbitrary JSON-serialisable payload plus optional Splunk
``sourcetype`` / ``index`` / ``time`` overrides. Subsystem-specific
factory helpers (see :mod:`anglerfish.forwarder.factories`) wrap the
typed data models into events without leaking subsystem knowledge into
the forwarder itself.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

__all__ = ["ForwarderEvent"]


class ForwarderEvent(BaseModel):
    """A single event submitted to the forwarder.

    The ``event`` mapping is forwarded verbatim into the Splunk HEC
    payload's ``event`` key. When the HEC submission fails, the same
    mapping is written to the JSONL fallback file alongside the
    envelope metadata, so no caller-visible information is lost.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    event: dict[str, Any] = Field(..., description="JSON-serialisable payload.")
    sourcetype: str | None = Field(default=None, max_length=64)
    index: str | None = Field(default=None, max_length=64)
    time: datetime | None = Field(default=None)
