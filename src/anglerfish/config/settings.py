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
from typing import Any, Self

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from anglerfish.config.models import (
    AuditConfig,
    BridgeConfig,
    CounterDeceptionConfig,
    CredentialsConfig,
    DashboardConfig,
    DefenseConfig,
    FingerprintConfig,
    GeoConfig,
    HoneytokensConfig,
    LogLevel,
    NarratorConfig,
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

    # Network interface names the wizard records (ANGLERFISH_BAIT_INTERFACE /
    # ANGLERFISH_SERVICE_INTERFACE). The lure resolves the bait interface's
    # current IPv4 at startup when listen_host is the unspecified address,
    # so a DHCP bait NIC (whose IP is unknown at wizard time) still binds.
    bait_interface: str | None = None
    service_interface: str | None = None

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
    counter_deception: CounterDeceptionConfig = Field(default_factory=CounterDeceptionConfig)
    narrator: NarratorConfig = Field(default_factory=NarratorConfig)
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

    @model_validator(mode="before")
    @classmethod
    def _rebase_state_paths_under_data_dir(cls, data: Any) -> Any:
        """Make data_dir the single base for runtime state (audit review M9).

        data_dir previously governed only the audit-tailer offset cache;
        the three on-disk state paths (sessions.db, credentials.db, the
        Tor-exit cache) embedded /var/lib/anglerfish independently, so
        ANGLERFISH_DATA_DIR moved almost nothing. When data_dir is set away
        from its default and a state path is still at its packaged
        /var/lib/anglerfish default, rebase it under data_dir so one knob
        relocates everything; an explicit override is left untouched. The
        audit LOG stays under /var/log by convention (logs, not data).

        Runs in ``before`` mode (and returns the input, not ``self``)
        because pydantic-settings ignores a non-self return from a
        top-level after-validator during ``__init__``.
        """
        if not isinstance(data, dict):
            return data
        default_base = Path("/var/lib/anglerfish")
        data_dir = Path(data.get("data_dir") or default_base)
        if data_dir == default_base:
            return data
        _rebase_subpath(
            data,
            "sessions",
            "database_path",
            default_base / "sessions.db",
            data_dir / "sessions.db",
        )
        _rebase_subpath(
            data,
            "credentials",
            "database_path",
            default_base / "credentials.db",
            data_dir / "credentials.db",
        )
        _rebase_subpath(
            data,
            "fingerprint",
            "tor_exit_list_path",
            default_base / "tor-exits.txt",
            data_dir / "tor-exits.txt",
        )
        return data


def _rebase_subpath(
    data: dict[str, Any],
    key: str,
    field: str,
    default_path: Path,
    new_path: Path,
) -> None:
    """Set ``data[key][field]`` to ``new_path`` only if it is currently
    absent or still at its packaged default (audit review M9). Handles the
    sub-config being absent, a dict (env / .env source), or a model
    instance (init kwarg); an explicit override is left untouched.
    """
    cur = data.get(key)
    if cur is None:
        data[key] = {field: str(new_path)}
    elif isinstance(cur, dict):
        if field not in cur or Path(cur[field]) == default_path:
            cur[field] = str(new_path)
    elif getattr(cur, field, None) == default_path:
        data[key] = cur.model_copy(update={field: new_path})


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
