"""Pydantic model for one generated honeytoken (Stage 11 slice 11.1).

A :class:`Honeytoken` is the unit the generator produces, the
registry persists (slice 11.2), the bridge ships in the
``fakefs_overlay`` payload (slice 11.3), and the callback
receiver looks up on a hit (slice 11.4).

The :attr:`Honeytoken.id` field is a 16-character RFC 4648
base32 string (alphabet ``A-Z2-7``) - the same alphabet AWS
uses for access-key-IDs. The full AWS access key ID is
``AKIA<id>``; the SSH public-key comment is
``honeytoken-<id>``. The callback receiver extracts the
16-char slice from incoming requests, looks up the matching
registry row, and audits ``bridge.honeytoken_callback``.

16 chars of base32 = 80 bits of randomness, more than enough
to make registry-ID guessing pointless and small enough that
the AWS access-key-ID format (``AKIA`` + 16 chars = 20 chars
total) matches the real AWS-IAM shape exactly.
"""

from __future__ import annotations

import base64
import secrets
from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

__all__ = ["Honeytoken", "HoneytokenKind", "new_lookup_id"]


HoneytokenKind = Literal["aws", "ssh_key"]
"""Which honeytoken shape the operator distributes.

* ``aws`` - AWS access key + secret block placed in
  ``/root/.aws/credentials`` (or wherever the persona overlay
  routes it).
* ``ssh_key`` - Ed25519 keypair placed in ``/root/.ssh/id_rsa``;
  the public-key comment carries ``honeytoken-<id>`` so
  operators can grep pastes / Shodan for it.

DB connection strings + generic API tokens are deferred to v1.1
per the Stage 11 design Out of scope.
"""


# 16 chars of RFC 4648 base32 = 80 bits. AWS access-key-IDs are
# exactly 16 chars after the AKIA prefix; using the same width +
# alphabet makes our IDs structurally indistinguishable from real
# IAM keys. The Pydantic ``pattern`` field on :class:`Honeytoken.id`
# pins the same shape on persisted rows.


def new_lookup_id() -> str:
    """Generate a fresh 16-char base32 honeytoken ID.

    Uses :func:`secrets.token_bytes` for cryptographic randomness;
    base32-encodes 10 bytes (80 bits) to land at exactly 16 chars
    with no padding. The output alphabet matches RFC 4648 standard
    base32 (``A-Z`` + ``2-7``) so the resulting string is a valid
    AWS access-key-ID suffix when prefixed with ``AKIA``.
    """
    return base64.b32encode(secrets.token_bytes(10)).decode("ascii")


class Honeytoken(BaseModel):
    """One generated honeytoken + provenance + callback URL.

    Constructed by :class:`HoneytokenGenerator`; persisted by
    the slice 11.2 ``SessionStore.register_honeytoken`` call.
    Frozen so registry-rehydrated copies cannot accidentally
    mutate.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str = Field(
        min_length=16,
        max_length=16,
        pattern=r"^[A-Z2-7]{16}$",
        description=(
            "16-char RFC 4648 base32 ID. Used as the AWS access-key-ID "
            "suffix (``AKIA<id>``) and as the SSH-key comment "
            "(``honeytoken-<id>``). The callback receiver extracts this "
            "from incoming requests for the registry lookup."
        ),
    )
    kind: HoneytokenKind
    payload: str = Field(
        min_length=1,
        max_length=8192,
        description=(
            "The file content the lure serves at ``placed_at``. For "
            "AWS this is an INI-formatted credentials block; for SSH "
            "this is the PEM-encoded private key (what the attacker "
            "would exfiltrate from ~/.ssh/id_rsa)."
        ),
    )
    callback_url: str = Field(
        min_length=1,
        max_length=512,
        description=(
            "The URL embedded in the token's payload. AWS attackers "
            "hit it implicitly via STS / S3 region resolution; SSH "
            "attackers do not (the SSH callback is operator-side: grep "
            "for the comment in Shodan / paste dumps)."
        ),
    )
    placed_at: str = Field(
        min_length=1,
        max_length=4096,
        description=(
            "The fakefs path the lure serves this payload from. Slice "
            "11.3 merges this into the SessionStartResponse fakefs_overlay "
            "dict alongside the Stage 9 + 10 entries."
        ),
    )
    source_ip: str | None = Field(
        default=None,
        max_length=64,
        description=(
            "Source IP of the session that triggered placement; NULL on "
            "static-base tokens that ship to every session. The "
            "registry lookup at session-open filters by this column."
        ),
    )
    session_id: UUID | None = Field(
        default=None,
        description=(
            "Session that triggered placement; NULL on static-base tokens. "
            "Persisted for operator triage; the bridge does NOT use it for "
            "lookup (source_ip is the cross-session join key)."
        ),
    )
    created_at: datetime

    def is_static_base(self) -> bool:
        """True iff this honeytoken ships to every session.

        Static-base tokens have ``source_ip`` and ``session_id`` both
        :data:`None`. The bridge registers them once at startup and
        merges them into every ``SessionStartResponse``.
        """
        return self.source_ip is None and self.session_id is None
