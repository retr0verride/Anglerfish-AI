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
from typing import Self

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from anglerfish.config.models import (
    AuditConfig,
    BridgeConfig,
    CredentialsConfig,
    DashboardConfig,
    DefenseConfig,
    FingerprintConfig,
    GeoConfig,
    HoneytokensConfig,
    LogLevel,
    OllamaConfig,
    PersonaConfig,
    RateLimitConfig,
    SessionStoreConfig,
    ThreatConfig,
)
from anglerfish.lure.config import LureConfig

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
    dashboard: DashboardConfig
    bridge: BridgeConfig = Field(default_factory=BridgeConfig)
    rate_limit: RateLimitConfig = Field(default_factory=RateLimitConfig)
    threat: ThreatConfig = Field(default_factory=ThreatConfig)
    defense: DefenseConfig = Field(default_factory=DefenseConfig)
    geo: GeoConfig = Field(default_factory=GeoConfig)
    fingerprint: FingerprintConfig = Field(default_factory=FingerprintConfig)
    lure: LureConfig = Field(default_factory=LureConfig)
    sessions: SessionStoreConfig = Field(default_factory=SessionStoreConfig)
    audit: AuditConfig = Field(default_factory=AuditConfig)
    persona: PersonaConfig = Field(default_factory=PersonaConfig)
    honeytokens: HoneytokensConfig = Field(default_factory=HoneytokensConfig)
    credentials: CredentialsConfig

    @model_validator(mode="after")
    def _validate_defense_scan_cap_covers_io_caps(self) -> Self:
        # Stage 1.8.5 invariant: the defense regex scan cap must be at
        # least as large as both the LLM response cap and the attacker
        # input cap. If scan_max_chars is smaller, leaks (or injections)
        # in the unscanned tail pass undetected — a silent defense
        # bypass with no operator-visible signal. Catch at config-load.
        if self.defense.scan_max_chars < self.ollama.max_response_chars:
            raise ValueError(
                f"defense.scan_max_chars ({self.defense.scan_max_chars}) must be >= "
                f"ollama.max_response_chars ({self.ollama.max_response_chars}). "
                "Otherwise the output filter only scans a prefix of long LLM responses "
                "and leaks in the tail pass undetected. Either raise scan_max_chars "
                "or lower max_response_chars.",
            )
        if self.defense.scan_max_chars < self.bridge.max_input_chars:
            raise ValueError(
                f"defense.scan_max_chars ({self.defense.scan_max_chars}) must be >= "
                f"bridge.max_input_chars ({self.bridge.max_input_chars}). "
                "Otherwise the injection scorer only scans a prefix of long attacker "
                "input and injections in the tail pass undetected. Either raise "
                "scan_max_chars or lower max_input_chars.",
            )
        # Pre-deploy sweep TODO-9: per-chunk cap MUST NOT exceed the
        # whole-stream cap; otherwise a single chunk could legally
        # carry more bytes than the assembled stream is allowed to,
        # which is operator-confusing and silently shifts the
        # truncation boundary.
        if self.ollama.max_chunk_chars > self.ollama.max_response_chars:
            raise ValueError(
                f"ollama.max_chunk_chars ({self.ollama.max_chunk_chars}) must be <= "
                f"ollama.max_response_chars ({self.ollama.max_response_chars}). "
                "A per-chunk cap above the whole-stream cap is operator-confusing "
                "and lets one chunk smuggle more bytes than the stream allows.",
            )
        return self


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
