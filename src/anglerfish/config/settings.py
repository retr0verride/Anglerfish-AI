"""Anglerfish AI settings root.

:class:`AnglerfishSettings` is the single source of truth for runtime
configuration. It is loaded from environment variables (prefix
``ANGLERFISH_``, nested delimiter ``__``) and from optional ``.env``
files in the working directory.

Two values have no default and must be supplied by the operator
(typically via the first-boot wizard):

* ``ANGLERFISH_DASHBOARD__SESSION_SECRET``
* ``ANGLERFISH_CREDENTIALS__ENCRYPTION_KEY``

The :func:`load_settings` helper produces a frozen, validated instance
and caches it for the lifetime of the process. Tests should construct
:class:`AnglerfishSettings` directly with explicit kwargs rather than
using the cache.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

from anglerfish.config.models import (
    BridgeConfig,
    CowrieConfig,
    CredentialsConfig,
    DashboardConfig,
    FingerprintConfig,
    GeoConfig,
    LogLevel,
    OllamaConfig,
    RateLimitConfig,
    SplunkConfig,
    ThreatConfig,
)

__all__ = ["AnglerfishSettings", "load_settings"]


class AnglerfishSettings(BaseSettings):
    """Root configuration object.

    Section attributes mirror the structure of :mod:`anglerfish.config.models`.
    Construct directly for tests, or call :func:`load_settings` to load
    from the process environment.
    """

    model_config = SettingsConfigDict(
        env_file=(".env", ".env.local"),
        env_file_encoding="utf-8",
        env_nested_delimiter="__",
        env_prefix="ANGLERFISH_",
        case_sensitive=False,
        extra="ignore",
        frozen=True,
    )

    log_level: LogLevel = LogLevel.INFO
    log_json: bool = True
    data_dir: Path = Path("/var/lib/anglerfish")

    ollama: OllamaConfig = Field(default_factory=OllamaConfig)
    splunk: SplunkConfig = Field(default_factory=SplunkConfig)
    cowrie: CowrieConfig = Field(default_factory=CowrieConfig)
    dashboard: DashboardConfig
    bridge: BridgeConfig = Field(default_factory=BridgeConfig)
    rate_limit: RateLimitConfig = Field(default_factory=RateLimitConfig)
    threat: ThreatConfig = Field(default_factory=ThreatConfig)
    geo: GeoConfig = Field(default_factory=GeoConfig)
    fingerprint: FingerprintConfig = Field(default_factory=FingerprintConfig)
    credentials: CredentialsConfig


@lru_cache(maxsize=1)
def load_settings() -> AnglerfishSettings:
    """Load and cache settings from the environment and ``.env`` files.

    Subsequent calls return the cached instance; this is the recommended
    entrypoint for production code. In tests, prefer constructing
    :class:`AnglerfishSettings` directly with explicit kwargs.
    """
    # The required-but-no-default fields (dashboard, credentials) are
    # populated by pydantic-settings from the environment at runtime.
    return AnglerfishSettings()
