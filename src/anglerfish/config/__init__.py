"""Pydantic-backed configuration layer.

The single source of truth for all Anglerfish runtime configuration. See
:class:`anglerfish.config.settings.AnglerfishSettings` for the root object.
Sub-section models live in :mod:`anglerfish.config.models`.
"""

from __future__ import annotations

from anglerfish.config.models import (
    BridgeConfig,
    CredentialsConfig,
    DashboardConfig,
    DefenseConfig,
    FingerprintConfig,
    GeoConfig,
    LogLevel,
    OllamaConfig,
    PersonaConfig,
    RateLimitConfig,
    ThreatConfig,
)
from anglerfish.config.settings import AnglerfishSettings, load_settings

__all__ = [
    "AnglerfishSettings",
    "BridgeConfig",
    "CredentialsConfig",
    "DashboardConfig",
    "DefenseConfig",
    "FingerprintConfig",
    "GeoConfig",
    "LogLevel",
    "OllamaConfig",
    "PersonaConfig",
    "RateLimitConfig",
    "ThreatConfig",
    "load_settings",
]
