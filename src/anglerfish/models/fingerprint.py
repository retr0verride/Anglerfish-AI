"""Shared data models for the fingerprint subsystem."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

__all__ = ["SessionFingerprint", "SshBannerInfo"]


class SshBannerInfo(BaseModel):
    """Parsed SSH client identification string.

    Per RFC 4253 §4.2 the banner has the form
    ``SSH-protoversion-softwareversion[ comments]\\r\\n``. All fields
    except ``raw`` may be :data:`None` if the banner is malformed or
    missing pieces.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    raw: str = Field(..., max_length=255)
    protocol: str | None = Field(default=None, max_length=255)
    software: str | None = Field(default=None, max_length=255)
    software_name: str | None = Field(default=None, max_length=255)
    software_version: str | None = Field(default=None, max_length=255)
    comments: str | None = Field(default=None, max_length=255)


class SessionFingerprint(BaseModel):
    """Network-level fingerprint of a single attacker session."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    source_ip: str
    ssh_banner: SshBannerInfo | None = None
    hassh: str | None = Field(default=None, pattern=r"^[0-9a-f]{32}$")
    ja3: str | None = Field(default=None, pattern=r"^[0-9a-f]{32}$")
    is_tor_exit: bool = False
