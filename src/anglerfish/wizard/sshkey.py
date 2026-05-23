"""OpenSSH public-key validation for the wizard.

The wizard accepts a single ``authorized_keys`` line from the operator
and installs it as the operator account's sole key. We validate the
format strictly to prevent two things:

* Multi-line input (an attacker pasting an extra ``\\n`` followed by
  arbitrary text would extend the file with anything they want).
* Unsupported key types — ED25519 and RSA are accepted; everything
  else is rejected, on the grounds that an operator pasting an
  unusual key is probably making a mistake we'd rather catch now.

This module never touches the filesystem. The wizard's render layer
formats the key into the ``authorized_keys`` body; this module only
parses and validates the input string.
"""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass

__all__ = [
    "MAX_KEY_BLOB_BYTES",
    "MIN_KEY_BLOB_BYTES",
    "SshPubKey",
    "SshPubKeyError",
    "parse_ssh_pubkey",
]


MIN_KEY_BLOB_BYTES = 32
MAX_KEY_BLOB_BYTES = 8192

_ALLOWED_TYPES = frozenset(
    {
        "ssh-ed25519",
        "ssh-rsa",
        "ecdsa-sha2-nistp256",
        "ecdsa-sha2-nistp384",
        "ecdsa-sha2-nistp521",
        "sk-ssh-ed25519@openssh.com",
        "sk-ecdsa-sha2-nistp256@openssh.com",
    },
)


class SshPubKeyError(ValueError):
    """Raised when an SSH public key line fails parsing or validation."""


@dataclass(frozen=True)
class SshPubKey:
    """A parsed OpenSSH public-key line."""

    key_type: str
    blob: str
    comment: str | None

    def to_authorized_keys_line(self) -> str:
        """Render the key back to a canonical single-line form."""
        comment = f" {self.comment}" if self.comment else ""
        return f"{self.key_type} {self.blob}{comment}"


def parse_ssh_pubkey(text: str) -> SshPubKey:
    """Parse and validate a single-line OpenSSH public key.

    Raises :class:`SshPubKeyError` on any of:

    * input is not a single line
    * line has fewer than two whitespace-separated tokens
    * key type is not in the supported set
    * base64 blob is malformed
    * decoded blob length is outside the sane range

    Returns:
        A :class:`SshPubKey` with the type, blob, and optional comment.
    """
    if not isinstance(text, str):
        raise SshPubKeyError(f"expected str, got {type(text).__name__}")

    # Reject multi-line / CR input BEFORE stripping; strip() would hide a
    # trailing '\n attacker-key' that we must not accept.
    if "\n" in text or "\r" in text:
        raise SshPubKeyError("key must be a single line")
    stripped = text.strip()
    if not stripped:
        raise SshPubKeyError("key is empty")

    parts = stripped.split()
    if len(parts) < 2:
        raise SshPubKeyError(
            "key must have at least <type> <base64> tokens",
        )

    # Strict format: no SSH options field. Operators wanting per-key
    # restrictions can edit /home/<user>/.ssh/authorized_keys directly.
    key_type = parts[0]
    blob = parts[1]
    comment = " ".join(parts[2:]) if len(parts) > 2 else None

    if key_type not in _ALLOWED_TYPES:
        raise SshPubKeyError(
            f"unsupported key type {key_type!r}; allowed: " + ", ".join(sorted(_ALLOWED_TYPES)),
        )

    try:
        decoded = base64.b64decode(blob, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise SshPubKeyError(f"invalid base64 blob: {exc}") from exc

    if not MIN_KEY_BLOB_BYTES <= len(decoded) <= MAX_KEY_BLOB_BYTES:
        raise SshPubKeyError(
            f"key blob length out of range: {len(decoded)} bytes "
            f"(expected {MIN_KEY_BLOB_BYTES}..{MAX_KEY_BLOB_BYTES})",
        )

    if comment is not None:
        # Forbid control chars in the comment — they'd break the file.
        if any(ord(c) < 0x20 or ord(c) == 0x7F for c in comment):
            raise SshPubKeyError("control characters in key comment")
        if len(comment) > 256:
            raise SshPubKeyError("key comment too long (max 256 chars)")

    return SshPubKey(key_type=key_type, blob=blob, comment=comment)
