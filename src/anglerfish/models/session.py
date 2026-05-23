"""Shared runtime data models for sessions and bridge responses.

These types travel between the bridge, the forwarder, the threat engine,
and the dashboard. They are frozen Pydantic models so that consumers can
safely cache or pass them across task boundaries.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

__all__ = [
    "BridgeResponse",
    "CommandTurn",
    "ResponseSource",
    "SessionSnapshot",
]


class ResponseSource(StrEnum):
    """Where the bridge's reply for a given command came from.

    * ``AI`` — produced by the LLM call, or by deterministic in-bridge
      handling (``cd``, blank input) of commands the LLM should not be
      asked to interpret.
    * ``FALLBACK`` — the LLM call failed (Ollama unavailable, rate
      limited, malformed response) and a scripted response was used.
    * ``REJECTED`` — the LLM call failed and fallbacks are disabled, so
      no response text is returned.
    """

    AI = "ai"
    FALLBACK = "fallback"
    REJECTED = "rejected"


class CommandTurn(BaseModel):
    """One attacker command paired with the response Anglerfish returned."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    command: str
    response: str
    source: ResponseSource
    timestamp: datetime
    latency_ms: float = Field(ge=0.0)


class BridgeResponse(BaseModel):
    """Result of :meth:`anglerfish.bridge.AIBridgeService.handle_command`."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    text: str
    source: ResponseSource
    latency_ms: float = Field(ge=0.0)


class SessionSnapshot(BaseModel):
    """Immutable summary of a session at a point in time.

    Produced by :meth:`anglerfish.bridge.SessionContext.snapshot` and
    consumed by the forwarder and dashboard.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    session_id: UUID
    source_ip: str
    username: str
    fake_hostname: str
    fake_username: str
    fake_cwd: str
    started_at: datetime
    last_activity_at: datetime
    turns: tuple[CommandTurn, ...]
