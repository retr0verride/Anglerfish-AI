"""Credential intelligence database with at-rest encryption.

Public surface:

* :class:`CredentialStore` - async SQLite-backed store. Use as an
  async context manager or call :meth:`open` / :meth:`aclose`
  explicitly.
* :class:`CredentialCipher` - exposed so :func:`rotate_key` and
  test harnesses can reuse the same key-derivation scheme.
"""

from __future__ import annotations

from anglerfish.credentials.crypto import CredentialCipher
from anglerfish.credentials.rotation import RotationError, RotationResult, rotate_key
from anglerfish.credentials.storage import CredentialStore

__all__ = [
    "CredentialCipher",
    "CredentialStore",
    "RotationError",
    "RotationResult",
    "rotate_key",
]
