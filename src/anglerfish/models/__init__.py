"""Shared data models used across :mod:`anglerfish` subsystems.

These are not configuration — they are the runtime record types
(sessions, command turns, bridge responses, threat assessments,
network fingerprints, geo records, credential records) that producer
subsystems emit and that the persistent session store, the dashboard,
and the credential store consume.
"""

from __future__ import annotations

from anglerfish.models.credentials import CredentialRecord, CredentialStats
from anglerfish.models.fingerprint import SessionFingerprint, SshBannerInfo
from anglerfish.models.geo import GeoRecord
from anglerfish.models.intent import IntentSummary
from anglerfish.models.session import (
    BridgeChunk,
    BridgeResponse,
    CommandTurn,
    ResponseSource,
    SessionSnapshot,
)
from anglerfish.models.threat import ThreatAssessment, ThreatTechnique

__all__ = [
    "BridgeChunk",
    "BridgeResponse",
    "CommandTurn",
    "CredentialRecord",
    "CredentialStats",
    "GeoRecord",
    "IntentSummary",
    "ResponseSource",
    "SessionFingerprint",
    "SessionSnapshot",
    "SshBannerInfo",
    "ThreatAssessment",
    "ThreatTechnique",
]
