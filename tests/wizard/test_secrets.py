"""Tests for :mod:`anglerfish.wizard.secrets`."""

from __future__ import annotations

import base64

from anglerfish.wizard.secrets import (
    generate_encryption_key,
    generate_session_secret,
)


def test_session_secret_length() -> None:
    secret = generate_session_secret()
    # 32 bytes URL-safe base64 → 43 chars (no padding).
    assert len(secret) == 43


def test_session_secret_uniqueness() -> None:
    secrets_seen = {generate_session_secret() for _ in range(8)}
    assert len(secrets_seen) == 8


def test_session_secret_url_safe_alphabet() -> None:
    secret = generate_session_secret()
    allowed = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")
    assert set(secret) <= allowed


def test_encryption_key_decodes_to_32_bytes() -> None:
    key = generate_encryption_key()
    decoded = base64.b64decode(key, validate=True)
    assert len(decoded) == 32


def test_encryption_key_uniqueness() -> None:
    keys = {generate_encryption_key() for _ in range(8)}
    assert len(keys) == 8
