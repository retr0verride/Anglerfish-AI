"""Shared data models used across :mod:`anglerfish` subsystems.

These are not configuration — they are the runtime record types
(sessions, command turns, bridge responses, threat assessments,
network fingerprints, geo records, credential records) that producer
subsystems emit and that the forwarder and dashboard consume.
"""

from __future__ import annotations

from anglerfish.models.credentials import CredentialRecord, CredentialStats
from anglerfish.models.fingerprint import SessionFingerprint, SshBannerInfo
from anglerfish.models.geo import GeoRecord
from anglerfish.models.session import (
    BridgeResponse,
    CommandTurn,
    ResponseSource,
    SessionSnapshot,
)
from anglerfish.models.threat import ThreatAssessment, ThreatTechnique

__all__ = [
    "BridgeResponse",
    "CommandTurn",
    "CredentialRecord",
    "CredentialStats",
    "GeoRecord",
    "ResponseSource",
    "SessionFingerprint",
    "SessionSnapshot",
    "SshBannerInfo",
    "ThreatAssessment",
    "ThreatTechnique",
]
