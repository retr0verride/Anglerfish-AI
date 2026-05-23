"""Shared data models for the credential intelligence store."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

__all__ = ["CredentialRecord", "CredentialStats"]


class CredentialRecord(BaseModel):
    """One unique (source_ip, username, password) attempt."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    source_ip: str
    username: str
    password: str
    first_seen: datetime
    last_seen: datetime
    attempt_count: int = Field(ge=1)


class CredentialStats(BaseModel):
    """Aggregate statistics over the credential intelligence database."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    total_attempts: int = Field(ge=0)
    unique_combinations: int = Field(ge=0)
    unique_usernames: int = Field(ge=0)
    unique_passwords: int = Field(ge=0)
    unique_source_ips: int = Field(ge=0)
