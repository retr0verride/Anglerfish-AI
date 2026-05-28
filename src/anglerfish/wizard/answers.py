"""Wizard answer and output models.

:class:`WizardAnswers` is the operator-supplied data the wizard needs
in order to produce a working honeypot. It is the single source of
truth that the wizard persists to ``/etc/anglerfish/wizard.json`` so
that ``anglerfish-wizard --reconfigure`` can replay it.

:class:`WizardOutput` records what the wizard *did* — which files were
written, whether secrets were generated — so callers (the systemd
firstboot unit) can take follow-up action and record the run for audit.

Two kinds of secrets are handled differently:

* **Operator-supplied secrets** (``dashboard_admin_password_hash``,
  ``maxmind_license_key``) are stored on :class:`WizardAnswers` as
  ``SecretStr`` fields so tracebacks and repr() calls show
  ``SecretStr('**********')``. They also round-trip to
  ``/etc/anglerfish/wizard.json`` as plaintext via the per-field
  ``field_serializer`` so ``--reconfigure``'s "blank to keep" flow
  works. wizard.json is 0600 + root-owned in production; that is
  the trust boundary, not the in-memory masking.
* **Auto-generated secrets** (session_secret, encryption_key,
  bridge_secret) are *not* stored on :class:`WizardAnswers`. They
  are regenerated on every wizard run and land only in
  ``/etc/anglerfish/anglerfish.env`` (mode 0600). Operators who
  run ``--reconfigure`` should expect to restart the bridge and
  dashboard afterwards because these values change.
"""

from __future__ import annotations

from pathlib import Path
from typing import Self

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    HttpUrl,
    IPvAnyAddress,
    SecretStr,
    field_serializer,
    model_validator,
)

__all__ = ["NetworkConfig", "WizardAnswers", "WizardOutput"]


class NetworkConfig(BaseModel):
    """Per-NIC IP configuration. DHCP by default; static when ``dhcp=False``."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    dhcp: bool = Field(default=True)
    address: str | None = Field(
        default=None,
        description="Static IPv4 or IPv6 address in CIDR form, e.g. 10.0.0.5/24.",
        max_length=64,
    )
    gateway: IPvAnyAddress | None = Field(default=None)
    dns: tuple[IPvAnyAddress, ...] = Field(default=())

    @model_validator(mode="after")
    def _static_needs_address_and_gateway(self) -> Self:
        if not self.dhcp:
            if self.address is None:
                raise ValueError("static network config requires `address`")
            if self.gateway is None:
                raise ValueError("static network config requires `gateway`")
        return self


class WizardAnswers(BaseModel):
    """Operator-supplied configuration choices (never includes secrets)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    terms_acknowledged: bool = Field(...)
    vm_hostname: str = Field(
        default="anglerfish-honeypot",
        min_length=1,
        max_length=63,
        description="Host operating-system hostname (not the lure's fake hostname).",
    )

    # NIC assignment + per-NIC IP config
    bait_interface: str = Field(..., min_length=1, max_length=32)
    service_interface: str = Field(..., min_length=1, max_length=32)
    bait_network: NetworkConfig = Field(default_factory=NetworkConfig)
    service_network: NetworkConfig = Field(default_factory=NetworkConfig)

    # Operator access
    operator_username: str = Field(
        default="anglerfish-ops",
        min_length=1,
        max_length=32,
    )
    operator_ssh_pubkey: str | None = Field(
        default=None,
        description=(
            "Full authorized_keys-style line for the operator account. "
            "If None, no key is installed and operators must use the noVNC "
            "console (or run --reconfigure later to add one)."
        ),
        max_length=4096,
    )

    # Dashboard authentication
    dashboard_admin_username: str = Field(
        default="admin",
        min_length=1,
        max_length=64,
    )
    dashboard_admin_password_hash: SecretStr | None = Field(
        default=None,
        description=(
            "bcrypt-hashed dashboard admin password. Set by the wizard from "
            "the operator's plaintext input. None ⇒ dashboard runs in open "
            "mode (only safe behind a fully-isolated service NIC). "
            "SecretStr ⇒ tracebacks and unintended repr() calls show "
            "``SecretStr('**********')`` rather than the bcrypt hash; "
            "a custom ``field_serializer`` unwraps to plaintext for the "
            "on-disk JSON so --reconfigure's blank-to-keep round-trip "
            "stays intact. Closed via pre-deploy sweep TODO-7."
        ),
    )

    # AI inference
    ollama_endpoint: HttpUrl
    ollama_trusted_remote_host: IPvAnyAddress | None = None
    ollama_model: str = Field(default="qwen3:14b", min_length=1, max_length=128)

    # Honeypot persona
    fake_hostname: str = Field(default="srv-prod-01", min_length=1, max_length=63)
    fake_username: str = Field(default="root", min_length=1, max_length=32)

    # Optional threat-alert webhook (Slack, PagerDuty, ...). Bridge fires
    # against this URL on alert; absence is fine.
    threat_alert_webhook: HttpUrl | None = None

    # Geo enrichment — MaxMind licence key is optional; without it
    # operators must drop pre-downloaded GeoLite2 .mmdb files in place.
    maxmind_license_key: SecretStr | None = Field(
        default=None,
        description=(
            "MaxMind licence key. When supplied, the first-boot oneshot "
            "anglerfish-geo-update.service downloads the GeoLite2-City "
            "and GeoLite2-ASN databases. SecretStr per pre-deploy sweep "
            "TODO-7; the same field_serializer that handles "
            "dashboard_admin_password_hash unwraps this for on-disk JSON."
        ),
    )

    # Stage 11: decoy data poisoning. Opt-in via wizard. The doc
    # acknowledgement gate fires before the URL prompt; declining
    # leaves honeytokens disabled (the runtime env-file emits no
    # ANGLERFISH_HONEYTOKENS__* lines).
    honeytokens_enabled: bool = Field(
        default=False,
        description=(
            "Stage 11 opt-in. False ⇒ no honeytokens generated or "
            "distributed; the bridge ignores the honeytoken placement "
            "service. True requires honeytokens_callback_base_url to "
            "be set; the wizard enforces this before writing the env "
            "file."
        ),
    )
    honeytokens_callback_base_url: HttpUrl | None = Field(
        default=None,
        description=(
            "Public-reachable HTTPS URL the operator binds the Stage 11 "
            "callback receiver at. Embedded in every generated token; "
            "operators front it with their own reverse proxy."
        ),
    )

    # Stage 12: active counter-deception. Opt-in via the wizard's
    # heaviest acknowledgement gate. Declining leaves it disabled
    # (the env file comments out ANGLERFISH_COUNTER_DECEPTION__ENABLED).
    # Mode + engagement_threshold are NOT prompted; they default in
    # CounterDeceptionConfig (both / 70) and the operator tunes them
    # in the env file or via the dashboard. No callback URL is needed
    # (unlike Stage 11), so a single bool captures the wizard answer.
    counter_deception_enabled: bool = Field(
        default=False,
        description=(
            "Stage 12 opt-in. False ⇒ the bridge never engages counter-"
            "deception. True requires the operator to have acknowledged "
            "the THREAT_MODEL.md Active counter-deception section in the "
            "wizard. Mode + threshold use CounterDeceptionConfig defaults."
        ),
    )

    @model_validator(mode="after")
    def _honeytokens_need_callback_url(self) -> Self:
        if self.honeytokens_enabled and self.honeytokens_callback_base_url is None:
            raise ValueError(
                "honeytokens_enabled=True requires honeytokens_callback_base_url",
            )
        return self

    @model_validator(mode="after")
    def _secret_length_bounds(self) -> Self:
        """Re-apply the length bounds the SecretStr upgrade dropped.

        Pydantic's ``min_length`` / ``max_length`` on a ``Field`` do
        not apply to ``SecretStr`` (the inner string is opaque to
        Pydantic). The bounds matched the pre-sweep ``str`` typing
        and prevent operator-pasted garbage from landing in the env
        file. Closed via pre-deploy sweep TODO-7.
        """
        if self.dashboard_admin_password_hash is not None:
            length = len(self.dashboard_admin_password_hash.get_secret_value())
            if length == 0 or length > 256:
                raise ValueError(
                    f"dashboard_admin_password_hash length {length} outside (0, 256]",
                )
        if self.maxmind_license_key is not None:
            length = len(self.maxmind_license_key.get_secret_value())
            if length < 8 or length > 64:
                raise ValueError(
                    f"maxmind_license_key length {length} outside [8, 64]",
                )
        return self

    @field_serializer("dashboard_admin_password_hash", "maxmind_license_key", when_used="json")
    def _unwrap_secret(self, value: SecretStr | None) -> str | None:
        """Emit the SecretStr's plaintext to the on-disk wizard.json.

        Closed via pre-deploy sweep TODO-7. The default JSON
        serialisation for SecretStr is the masked literal
        ``"**********"`` which would round-trip into a SecretStr
        whose ``.get_secret_value()`` returns ``"**********"`` -
        silently replacing the bcrypt hash on every --reconfigure.
        The wizard.json file is 0600 + root-owned in production,
        so plaintext on-disk is the existing trust boundary;
        SecretStr only adds repr/traceback masking on top of that.
        """
        return value.get_secret_value() if value is not None else None


class WizardOutput(BaseModel):
    """Outcome of a wizard run — file paths and metadata for audit."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    env_path: Path
    nftables_path: Path
    bait_network_path: Path
    service_network_path: Path
    hostname_path: Path
    answers_path: Path
    authorized_keys_path: Path | None = None

    dashboard_session_secret_generated: bool
    credentials_encryption_key_generated: bool
    bridge_shared_secret_generated: bool

    bait_interface: str
    service_interface: str

    preflight_results: tuple[str, ...] = Field(
        default=(),
        description="Human-readable preflight check results (one per service).",
    )
