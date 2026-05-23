"""Pydantic-backed configuration layer.

The single source of truth for all Anglerfish runtime configuration. See
:class:`anglerfish.config.settings.AnglerfishSettings` for the root object.
Sub-section models live in :mod:`anglerfish.config.models`.
"""

from __future__ import annotations

from anglerfish.config.models import (
    BridgeConfig,
    CowrieConfig,
    CredentialsConfig,
    DashboardConfig,
    DefenseConfig,
    FingerprintConfig,
    GeoConfig,
    LogLevel,
    OllamaConfig,
    RateLimitConfig,
    SplunkConfig,
    ThreatConfig,
)
from anglerfish.config.settings import AnglerfishSettings, load_settings

__all__ = [
    "AnglerfishSettings",
    "BridgeConfig",
    "CowrieConfig",
    "CredentialsConfig",
    "DashboardConfig",
    "DefenseConfig",
    "FingerprintConfig",
    "GeoConfig",
    "LogLevel",
    "OllamaConfig",
    "RateLimitConfig",
    "SplunkConfig",
    "ThreatConfig",
    "load_settings",
]
