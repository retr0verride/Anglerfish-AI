"""AES-GCM encryption + HMAC fingerprinting for credential records.

Two derived keys live behind one operator-supplied master key:

* The **AES-GCM key** is the master key itself — used to encrypt the
  ``username`` and ``password`` fields. Each encryption uses a fresh
  random 12-byte nonce. The 16-byte authentication tag is included in
  the ciphertext returned by :mod:`cryptography`'s AESGCM API.
* The **HMAC fingerprint key** is derived from the master key by
  HMAC-SHA256 over a fixed application-context string. It is used to
  compute deterministic 32-byte fingerprints of the plaintext that
  the database can ``SELECT WHERE ...`` on without decrypting any
  records — that lets us deduplicate identical attempts and answer
  unique-counts cheaply.

Both keys live only in memory; only the master key persists in
configuration. Splitting the role of "find again" from the role of
"encrypt at rest" follows the same principle as keyed search in
encrypted databases: the search key never touches the ciphertext.
"""

from __future__ import annotations

import base64
import binascii
import os
from typing import Final

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

__all__ = ["CredentialCipher"]


_AES_KEY_SIZE: Final[int] = 32
_NONCE_SIZE: Final[int] = 12
_HMAC_CONTEXT: Final[bytes] = b"anglerfish-credentials-fingerprint-v1"


class CredentialCipher:
    """Holds the encryption + fingerprint keys derived from one master key."""

    __slots__ = ("_aes", "_hmac_key")

    def __init__(self, master_key_b64: str) -> None:
        try:
            raw = base64.b64decode(master_key_b64, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise ValueError(
                "credentials master key must be standard base64 encoded",
            ) from exc
        if len(raw) != _AES_KEY_SIZE:
            raise ValueError(
                f"credentials master key must decode to {_AES_KEY_SIZE} bytes, got {len(raw)}",
            )
        self._aes = AESGCM(raw)
        self._hmac_key = self._derive_hmac_key(raw)

    @staticmethod
    def _derive_hmac_key(master: bytes) -> bytes:
        h = hmac.HMAC(master, hashes.SHA256())
        h.update(_HMAC_CONTEXT)
        return h.finalize()

    def encrypt(self, plaintext: str) -> tuple[bytes, bytes]:
        """Encrypt ``plaintext``; return ``(ciphertext, nonce)``."""
        if not isinstance(plaintext, str):
            raise TypeError(f"plaintext must be str, got {type(plaintext).__name__}")
        nonce = os.urandom(_NONCE_SIZE)
        ciphertext = self._aes.encrypt(nonce, plaintext.encode("utf-8"), None)
        return ciphertext, nonce

    def decrypt(self, ciphertext: bytes, nonce: bytes) -> str:
        """Decrypt ``(ciphertext, nonce)`` back to the plaintext string.

        Raises:
            ValueError: ciphertext tag verification failed (tampering or
                wrong key) or the result is not valid UTF-8.
        """
        if len(nonce) != _NONCE_SIZE:
            raise ValueError(f"nonce must be {_NONCE_SIZE} bytes, got {len(nonce)}")
        try:
            plaintext_bytes = self._aes.decrypt(nonce, ciphertext, None)
        except InvalidTag as exc:
            raise ValueError("credentials ciphertext authentication failed") from exc
        try:
            return plaintext_bytes.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError("decrypted credentials value is not valid UTF-8") from exc

    def fingerprint(self, value: str) -> bytes:
        """Return the deterministic 32-byte HMAC fingerprint of ``value``."""
        if not isinstance(value, str):
            raise TypeError(f"value must be str, got {type(value).__name__}")
        h = hmac.HMAC(self._hmac_key, hashes.SHA256())
        h.update(value.encode("utf-8"))
        return h.finalize()
