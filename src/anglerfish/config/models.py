"""Pydantic configuration models for Anglerfish AI.

Every Anglerfish subsystem reads its configuration from one of the
:class:`~pydantic.BaseModel` subclasses defined here, composed into the
single :class:`anglerfish.config.settings.AnglerfishSettings` root.

Two non-obvious invariants are enforced at validation time:

* :class:`OllamaConfig` requires the endpoint host to be either a
  loopback address or the IP literal stored in ``trusted_remote_host``.
  Hostnames other than ``localhost`` are rejected because DNS resolution
  could change between validation and use, and routing decisions for a
  honeypot must be auditable from the configuration alone.
* :class:`CredentialsConfig` requires ``encryption_key`` to decode to
  exactly 32 bytes. The credential intelligence database is encrypted
  at rest with that key.
"""

from __future__ import annotations

import base64
import binascii
import ipaddress
import re
from enum import StrEnum
from pathlib import Path
from typing import Self

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    HttpUrl,
    IPvAnyAddress,
    SecretStr,
    field_validator,
    model_validator,
)

__all__ = [
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
]


_LOOPBACK_HOSTNAMES = frozenset({"localhost"})
_HOSTNAME_RE = re.compile(r"^(?=.{1,63}$)[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?$")


def _strip_ipv6_brackets(host: str) -> str:
    """pydantic's HttpUrl wraps IPv6 hosts in square brackets; ipaddress rejects that form."""
    if len(host) >= 2 and host.startswith("[") and host.endswith("]"):
        return host[1:-1]
    return host


class LogLevel(StrEnum):
    """Standard library logging level names, exposed as a string enum."""

    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class OllamaConfig(BaseModel):
    """LLM inference endpoint and sampling parameters.

    The Ollama endpoint may live either on loopback (the default — when
    inference runs on the honeypot itself) or on a single explicitly
    trusted IP address (a separate GPU host on the service network).
    Any other endpoint is rejected at validation time.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    base_url: HttpUrl = Field(
        default=HttpUrl("http://127.0.0.1:11434/"),
        description="HTTP base URL of the Ollama server.",
    )
    trusted_remote_host: IPvAnyAddress | None = Field(
        default=None,
        description=(
            "Optional IP literal of a trusted non-loopback Ollama host. "
            "When set, base_url is permitted to point at this IP and no other."
        ),
    )
    model: str = Field(
        default="qwen3:14b",
        min_length=1,
        max_length=128,
        description=(
            "Ollama model tag. Default is qwen3:14b — Apache-2.0 "
            "licensed, Hugging Face-distributed, 14B params fits in "
            "12GB VRAM at Q4. Avoid deepseek-coder for production "
            "deployments: third-party security reviews have flagged "
            "CCP-aligned content moderation that surfaces in shell "
            "honeypot contexts. See docs/MODEL_SETUP.md."
        ),
    )
    request_timeout_s: float = Field(default=45.0, gt=0.0, le=600.0)
    connect_timeout_s: float = Field(default=5.0, gt=0.0, le=60.0)
    max_response_tokens: int = Field(default=512, gt=0, le=4096)
    max_response_chars: int = Field(default=8192, gt=0, le=65536)
    temperature: float = Field(default=0.4, ge=0.0, le=2.0)
    top_p: float = Field(default=0.9, ge=0.0, le=1.0)

    @model_validator(mode="after")
    def _validate_endpoint_host(self) -> Self:
        host_str = self.base_url.host
        if not host_str:
            raise ValueError("Ollama base_url must include a host")

        if self._host_is_loopback(host_str):
            return self

        if self.trusted_remote_host is None:
            raise ValueError(
                f"Ollama base_url host {host_str!r} is not loopback. "
                "Set trusted_remote_host to its IP address to allow it, "
                "or move the endpoint back to 127.0.0.1.",
            )

        host_ip = self._parse_host_as_ip(host_str)
        if host_ip is None:
            raise ValueError(
                f"Ollama base_url host {host_str!r} is not an IP literal. "
                "Hostnames other than 'localhost' are rejected because DNS "
                "resolution could change between validation and use.",
            )
        if host_ip != self.trusted_remote_host:
            raise ValueError(
                f"Ollama base_url host {host_str!r} does not match "
                f"trusted_remote_host {self.trusted_remote_host!s}.",
            )
        return self

    @staticmethod
    def _host_is_loopback(host: str) -> bool:
        if host.lower() in _LOOPBACK_HOSTNAMES:
            return True
        try:
            return ipaddress.ip_address(_strip_ipv6_brackets(host)).is_loopback
        except ValueError:
            return False

    @staticmethod
    def _parse_host_as_ip(
        host: str,
    ) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
        try:
            return ipaddress.ip_address(_strip_ipv6_brackets(host))
        except ValueError:
            return None


class SplunkConfig(BaseModel):
    """Splunk HTTP Event Collector (HEC) forwarder configuration."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    enabled: bool = Field(default=False)
    hec_url: HttpUrl | None = Field(default=None)
    hec_token: SecretStr | None = Field(default=None)
    index: str = Field(default="anglerfish", min_length=1, max_length=64)
    sourcetype: str = Field(default="anglerfish:session", min_length=1, max_length=64)
    verify_tls: bool = Field(default=True)
    timeout_s: float = Field(default=10.0, gt=0.0, le=120.0)
    fallback_path: Path = Field(default=Path("/var/lib/anglerfish/sessions.jsonl"))

    @model_validator(mode="after")
    def _require_url_and_token_when_enabled(self) -> Self:
        if self.enabled and (self.hec_url is None or self.hec_token is None):
            raise ValueError(
                "splunk.hec_url and splunk.hec_token are required when splunk.enabled is true.",
            )
        return self


class CowrieConfig(BaseModel):
    """Cowrie SSH/Telnet honeypot frontend configuration."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    log_path: Path = Field(default=Path("/var/log/cowrie/cowrie.json"))
    ssh_listen_port: int = Field(default=2222, ge=1, le=65535)
    telnet_listen_port: int = Field(default=2223, ge=1, le=65535)
    hostname: str = Field(default="srv-prod-01", min_length=1, max_length=63)

    @field_validator("hostname")
    @classmethod
    def _validate_hostname(cls, v: str) -> str:
        if not _HOSTNAME_RE.match(v):
            raise ValueError(
                f"hostname must be a valid RFC 1123 label, got {v!r}",
            )
        return v

    @model_validator(mode="after")
    def _ports_must_differ(self) -> Self:
        if self.ssh_listen_port == self.telnet_listen_port:
            raise ValueError(
                "cowrie.ssh_listen_port and cowrie.telnet_listen_port must be different.",
            )
        return self


class DashboardConfig(BaseModel):
    """FastAPI + WebSocket dashboard configuration."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    host: str = Field(default="127.0.0.1", min_length=1)
    port: int = Field(default=8420, ge=1, le=65535)
    enable_websockets: bool = Field(default=True)
    session_secret: SecretStr = Field(
        ...,
        description="Cookie signing secret. At least 32 characters.",
    )

    admin_username: str = Field(
        default="admin",
        min_length=1,
        max_length=64,
        description="Username for operator login.",
    )
    admin_password_hash: SecretStr | None = Field(
        default=None,
        description=(
            "bcrypt-hashed admin password. Generated by the wizard from the "
            "operator-supplied plaintext. When None the dashboard runs in "
            "open mode — only safe when nftables fully isolates the service NIC."
        ),
    )
    allowed_origins: tuple[str, ...] = Field(
        default=(),
        description=(
            "Allowed Origin header values for WebSocket upgrades. When empty, "
            "the dashboard's own http(s)://host:port pair is the only allowed "
            "origin. Add additional origins for reverse-proxy deployments."
        ),
    )

    @field_validator("session_secret")
    @classmethod
    def _validate_secret(cls, v: SecretStr) -> SecretStr:
        if len(v.get_secret_value()) < 32:
            raise ValueError(
                "dashboard.session_secret must be at least 32 characters.",
            )
        return v

    @field_validator("admin_password_hash")
    @classmethod
    def _validate_password_hash(cls, v: SecretStr | None) -> SecretStr | None:
        if v is None:
            return None
        raw = v.get_secret_value()
        # bcrypt hashes start with $2a$, $2b$, or $2y$ — sanity check format.
        if not (raw.startswith(("$2a$", "$2b$", "$2y$")) and len(raw) >= 59):
            raise ValueError(
                "dashboard.admin_password_hash must be a bcrypt hash "
                "(starts with $2a$, $2b$, or $2y$).",
            )
        return v


class BridgeConfig(BaseModel):
    """AI bridge behaviour parameters (orthogonal to the Ollama HTTP client)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    max_input_chars: int = Field(default=4096, gt=0, le=32768)
    history_window: int = Field(default=20, ge=0, le=200)
    fake_hostname: str = Field(default="srv-prod-01", min_length=1, max_length=63)
    fake_username: str = Field(default="root", min_length=1, max_length=32)
    fake_cwd: str = Field(default="/root", min_length=1, max_length=4096)
    enable_fallback: bool = Field(default=True)
    listen_host: str = Field(
        default="127.0.0.1",
        min_length=1,
        max_length=64,
        description="Address the bridge HTTP server binds to. MUST be loopback in prod.",
    )
    listen_port: int = Field(default=8421, ge=1, le=65535)
    shared_secret: SecretStr | None = Field(
        default=None,
        description=(
            "Bearer token required on every bridge HTTP request. The wizard "
            "generates a 32-byte URL-safe token and writes it to the env "
            "file shared by the bridge daemon and Cowrie."
        ),
    )

    @field_validator("fake_hostname")
    @classmethod
    def _validate_hostname(cls, v: str) -> str:
        if not _HOSTNAME_RE.match(v):
            raise ValueError(
                f"fake_hostname must be a valid RFC 1123 label, got {v!r}",
            )
        return v

    @field_validator("fake_cwd")
    @classmethod
    def _validate_cwd(cls, v: str) -> str:
        if not v.startswith("/"):
            raise ValueError(f"fake_cwd must be absolute (starts with /), got {v!r}")
        return v


class RateLimitConfig(BaseModel):
    """Bridge rate-limiting and queueing parameters."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    max_concurrent_requests: int = Field(default=8, ge=1, le=128)
    requests_per_session_per_minute: int = Field(default=30, ge=1, le=600)
    session_burst: int = Field(
        default=10,
        ge=1,
        le=100,
        description="Initial token-bucket capacity per session.",
    )
    queue_timeout_s: float = Field(default=10.0, gt=0.0, le=120.0)
    bucket_idle_eviction_s: float = Field(
        default=300.0,
        gt=0.0,
        le=3600.0,
        description="Drop per-session buckets after this idle period to bound memory.",
    )


class ThreatConfig(BaseModel):
    """Threat scoring + alerting configuration.

    ``alert_webhook_url`` is the only outbound destination Anglerfish posts
    threat-intel to. Its validation policy is *not* the same as the Ollama
    endpoint policy — webhooks point at third-party services (Slack,
    PagerDuty, OpsGenie) that necessarily use DNS names. Instead the
    validator enforces:

    * **HTTPS only.** Threat-intel payloads include source IPs, attempted
      commands, and ATT&CK technique tags. They go over TLS or they do
      not go at all.
    * **No IP-literals in private/loopback/link-local ranges.** Catches
      typos and config-management mistakes that would post threat data
      to internal services. Hostnames are allowed (Slack needs DNS); the
      service-NIC nftables egress policy in
      ``cowrie/nftables/anglerfish.nft`` is the runtime control.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    alert_threshold: int = Field(default=70, ge=0, le=100)
    alert_webhook_url: HttpUrl | None = Field(default=None)
    alert_webhook_timeout_s: float = Field(default=5.0, gt=0.0, le=60.0)

    @model_validator(mode="after")
    def _validate_webhook_url(self) -> Self:
        if self.alert_webhook_url is None:
            return self
        url = self.alert_webhook_url
        if url.scheme != "https":
            raise ValueError(
                f"threat.alert_webhook_url scheme {url.scheme!r} is not "
                "'https'. Webhook payloads contain threat intelligence and "
                "must be sent over TLS.",
            )
        host = url.host
        if not host:
            raise ValueError("threat.alert_webhook_url must include a host")
        try:
            ip = ipaddress.ip_address(_strip_ipv6_brackets(host))
        except ValueError:
            return self  # hostname — allowed, nftables is the runtime control
        if ip.is_loopback or ip.is_private or ip.is_link_local:
            raise ValueError(
                f"threat.alert_webhook_url host {host!r} is in a "
                "private/loopback/link-local range. Webhooks to internal "
                "addresses are blocked to prevent SSRF-style misconfiguration.",
            )
        return self


class DefenseConfig(BaseModel):
    """LLM-targeted-attack defense configuration.

    Three orthogonal defenses fed from this config:

    1. **Output filter** — post-processes every LLM response, catches
       leaks like "I am an AI", model names, conversational filler,
       markdown formatting. Binary fire on any pattern match. Disabled
       responses fall back to the scripted fallback module so the
       attacker sees indistinguishable output.

    2. **Injection scorer** — pre-processes every attacker command,
       scores against known prompt-injection signatures (override
       instructions, persona switch, special chat-template tokens, …).
       Score ≥ ``injection_threshold`` skips the LLM entirely and uses
       fallback. Stage 1 ships only explicit (severity 1.0) signatures;
       the threshold gates future heuristics.

    3. **Model integrity** — at bridge startup, verifies the Ollama
       model's blob/layer digest matches ``model_expected_hash``. If
       set and mismatched, the bridge refuses to start. If unset, a
       loud structured warning + audit-log entry surfaces the
       unverified state on every boot. Pins the layer digest (the
       GGUF blob's sha256), not the human-readable tag — defends
       against silent tag re-pointing.

    See ``docs/design/STAGE_1_llm_defense.md`` for the full
    architecture and threat model.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    output_filter_enabled: bool = Field(
        default=True,
        description=(
            "Post-filter LLM responses for leaks. Disable only for "
            "controlled-environment debugging; production must run with this on."
        ),
    )
    injection_filter_enabled: bool = Field(
        default=True,
        description=(
            "Pre-filter attacker input for prompt-injection signatures. "
            "Disable only for controlled-environment debugging."
        ),
    )
    injection_threshold: float = Field(
        default=0.7,
        ge=0.0,
        le=1.0,
        description=(
            "Score threshold above which the injection scorer fires and "
            "the LLM call is skipped. Stage 1 ships only severity-1.0 "
            "signatures (always fire regardless of threshold); this knob "
            "is forward-looking infrastructure for heuristic patterns "
            "added in later stages with telemetry."
        ),
    )
    scan_max_chars: int = Field(
        default=8192,  # mirrors _DEFAULT_SCAN_MAX_CHARS in bridge.defense
        ge=512,
        le=65536,
        description=(
            "Hard cap on bytes the defense regex engine scans per input. "
            "Bounds worst-case ReDoS exposure: regex engines without per-"
            "pattern timeouts (CPython < 3.13) cannot be allowed to chew "
            "on multi-MB inputs without pinning the event loop. The cap "
            "MUST be >= ollama.max_response_chars (otherwise leaks in "
            "the unscanned tail of a long LLM response pass undetected) "
            "and >= bridge.max_input_chars (same logic for attacker "
            "input). AnglerfishSettings enforces both invariants at "
            "validation time. Increase only if you also raise the "
            "response/input caps."
        ),
    )
    model_expected_hash: SecretStr | None = Field(
        default=None,
        description=(
            "Expected SHA256 of the Ollama model's blob layer digest. "
            "When set, bridge verifies at startup and refuses to start "
            "on mismatch. When unset, bridge logs a loud warning and "
            "writes a bridge.model_integrity_skipped audit entry on "
            "every startup. Capture the expected value from the model "
            "manifest with: jq -r '.layers[] | "
            'select(.mediaType == "application/vnd.ollama.image.model") '
            "| .digest' < ~/.ollama/models/manifests/.../<tag>"
        ),
    )
    pattern_overrides_path: Path | None = Field(
        default=None,
        description=(
            "Optional TOML file extending the in-tree default patterns "
            "in src/anglerfish/bridge/defense_patterns.py. Overrides are "
            "additive only — a malicious or buggy file can add false "
            "positives but never remove defenses. See "
            "docs/design/STAGE_1_llm_defense.md for the schema."
        ),
    )
    ollama_manifest_dir: Path | None = Field(
        default=None,
        description=(
            "Filesystem path to Ollama's `models/manifests` directory. "
            "Required when model_expected_hash is set. Common values: "
            "/usr/share/ollama/.ollama/models/manifests (Linux, official "
            "installer running as `ollama` user); ~/.ollama/models/manifests "
            "(user-installed Ollama). The bridge reads the layer digest from "
            "<manifest_dir>/registry.ollama.ai/library/<model>/<tag> at "
            "startup."
        ),
    )

    @field_validator("model_expected_hash")
    @classmethod
    def _validate_model_hash(cls, v: SecretStr | None) -> SecretStr | None:
        if v is None:
            return None
        raw = v.get_secret_value()
        # Accept either bare hex sha256 or the "sha256:..." prefix form
        # that jq returns from the Ollama manifest. Normalize: strip
        # prefix during the check, accept lowercase hex of length 64.
        candidate = raw.removeprefix("sha256:").lower()
        if len(candidate) != 64 or not all(c in "0123456789abcdef" for c in candidate):
            raise ValueError(
                "defense.model_expected_hash must be a SHA256 hex digest "
                "(64 lowercase hex chars), optionally prefixed with "
                "'sha256:'. Got: " + (raw[:80] + "..." if len(raw) > 80 else raw),
            )
        return v

    @model_validator(mode="after")
    def _validate_integrity_requires_manifest_dir(self) -> Self:
        # Enforce the cross-field invariant: if the operator is asking
        # for integrity verification, they must also tell us where the
        # Ollama manifest lives — otherwise the check would silently
        # fail to find anything and produce a confusing FileNotFoundError
        # at startup. Fail loudly at config time instead.
        if self.model_expected_hash is not None and self.ollama_manifest_dir is None:
            raise ValueError(
                "defense.model_expected_hash is set but defense.ollama_manifest_dir "
                "is not. Set ANGLERFISH_DEFENSE__OLLAMA_MANIFEST_DIR to the path "
                "of Ollama's models/manifests directory (commonly "
                "/usr/share/ollama/.ollama/models/manifests for systemd installs "
                "or ~/.ollama/models/manifests for user installs).",
            )
        return self


class GeoConfig(BaseModel):
    """MaxMind GeoLite2 database paths and (optional) operator licence key.

    The licence key enables the on-VM ``anglerfish geo update`` flow:
    the unit runs once at first boot (and weekly thereafter) to fetch
    fresh City + ASN databases from MaxMind. When the key is absent
    operators may still drop pre-downloaded ``.mmdb`` files at the
    configured paths; the geo subsystem treats both flows identically.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    city_db_path: Path | None = Field(default=None)
    asn_db_path: Path | None = Field(default=None)
    maxmind_license_key: SecretStr | None = Field(
        default=None,
        description=(
            "Operator-supplied MaxMind licence key. When set, "
            "`anglerfish geo update` fetches GeoLite2-City and GeoLite2-ASN "
            "and writes them to the configured paths. When unset, the "
            "command is a no-op (operators may pre-stage the files manually)."
        ),
    )

    @field_validator("maxmind_license_key")
    @classmethod
    def _validate_license_key(cls, v: SecretStr | None) -> SecretStr | None:
        if v is None:
            return None
        raw = v.get_secret_value()
        # MaxMind issues 16-character alphanumeric keys; allow a small
        # range so re-issued keys don't trip validation.
        if not (8 <= len(raw) <= 64 and raw.isalnum()):
            raise ValueError(
                "MaxMind licence key must be 8 to 64 alphanumeric characters",
            )
        return v

    @property
    def enabled(self) -> bool:
        return self.city_db_path is not None or self.asn_db_path is not None


class FingerprintConfig(BaseModel):
    """Session fingerprinting and threat-actor lookup."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    tor_exit_list_path: Path = Field(
        default=Path("/var/lib/anglerfish/tor-exits.txt"),
    )
    tor_exit_refresh_interval_s: float = Field(
        default=3600.0,
        gt=0.0,
        le=86400.0,
    )


class CredentialsConfig(BaseModel):
    """Credential intelligence database with at-rest encryption."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    database_path: Path = Field(default=Path("/var/lib/anglerfish/credentials.db"))
    encryption_key: SecretStr = Field(
        ...,
        description=(
            "Base64-encoded 32-byte key for AES-GCM encryption of "
            "credential records. Generated by the first-boot wizard."
        ),
    )
    max_unique_per_source_ip: int = Field(
        default=1000,
        ge=0,
        le=1_000_000,
        description=(
            "Maximum number of distinct (username, password) pairs the "
            "credential store will retain per source IP. Once an attacker "
            "passes the cap, additional unique attempts are dropped — "
            "existing rows still increment their attempt_count. Set to 0 "
            "to disable the cap (unbounded growth — only sensible in a "
            "closed lab). The cap exists because the HMAC dedup catches "
            "repeated attempts but not unique-each-time creds-stuffing, "
            "which can otherwise fill the disk."
        ),
    )

    @field_validator("encryption_key")
    @classmethod
    def _validate_encryption_key(cls, v: SecretStr) -> SecretStr:
        raw = v.get_secret_value()
        try:
            decoded = base64.b64decode(raw, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise ValueError(
                "credentials.encryption_key must be standard base64 encoded.",
            ) from exc
        if len(decoded) != 32:
            raise ValueError(
                f"credentials.encryption_key must decode to exactly 32 bytes, got {len(decoded)}.",
            )
        return v
