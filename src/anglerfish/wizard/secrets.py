"""Cryptographically strong secret generation.

All secrets the wizard generates are 32 bytes drawn from the OS
:mod:`secrets` module. Three encodings are exposed because the three
downstream consumers want different things:

* The **dashboard session secret** is a 32-byte URL-safe string used
  directly as a cookie signing key. URL-safe base64 produces 43 ASCII
  characters with no padding, easily round-trippable through shell
  environments.
* The **credentials encryption key** is the same 32 bytes encoded in
  standard base64 (with padding), because the credential store
  decodes it via :func:`base64.b64decode` and expects exactly 32 raw
  bytes back.
* The **bridge shared secret** is a URL-safe 32-byte token used as the
  ``Authorization: Bearer`` value between the lure and the bridge. It
  rides in a ``.env`` file so URL-safe alphabet avoids quoting drama.
"""

from __future__ import annotations

import base64
import secrets

__all__ = [
    "generate_bridge_secret",
    "generate_encryption_key",
    "generate_session_secret",
]


_SECRET_BYTES = 32


def generate_session_secret() -> str:
    """Return a 43-character URL-safe random string (32 bytes of entropy)."""
    return secrets.token_urlsafe(_SECRET_BYTES)


def generate_encryption_key() -> str:
    """Return a standard-base64-encoded 32-byte random key with padding."""
    raw = secrets.token_bytes(_SECRET_BYTES)
    return base64.b64encode(raw).decode("ascii")


def generate_bridge_secret() -> str:
    """Return a 43-character URL-safe random bridge auth token (32 bytes)."""
    return secrets.token_urlsafe(_SECRET_BYTES)
