"""Tests for :class:`anglerfish.credentials.CredentialCipher`."""

from __future__ import annotations

import base64

import pytest

from anglerfish.credentials.crypto import CredentialCipher


def _key() -> str:
    return base64.b64encode(b"\x07" * 32).decode("ascii")


def test_round_trip() -> None:
    cipher = CredentialCipher(_key())
    ct, nonce = cipher.encrypt("hunter2")
    assert cipher.decrypt(ct, nonce) == "hunter2"


def test_encrypt_produces_fresh_nonce() -> None:
    cipher = CredentialCipher(_key())
    _, n1 = cipher.encrypt("p")
    _, n2 = cipher.encrypt("p")
    assert n1 != n2


def test_encrypt_handles_unicode() -> None:
    cipher = CredentialCipher(_key())
    ct, nonce = cipher.encrypt("pässword🔑")
    assert cipher.decrypt(ct, nonce) == "pässword🔑"


def test_fingerprint_deterministic() -> None:
    cipher = CredentialCipher(_key())
    a = cipher.fingerprint("admin")
    b = cipher.fingerprint("admin")
    assert a == b
    assert len(a) == 32


def test_fingerprint_differs_per_input() -> None:
    cipher = CredentialCipher(_key())
    assert cipher.fingerprint("admin") != cipher.fingerprint("root")


def test_fingerprint_differs_across_keys() -> None:
    cipher_a = CredentialCipher(base64.b64encode(b"a" * 32).decode())
    cipher_b = CredentialCipher(base64.b64encode(b"b" * 32).decode())
    assert cipher_a.fingerprint("admin") != cipher_b.fingerprint("admin")


def test_construction_rejects_non_base64() -> None:
    with pytest.raises(ValueError):
        CredentialCipher("not!base64!")


def test_construction_rejects_wrong_length() -> None:
    short = base64.b64encode(b"\x00" * 16).decode("ascii")
    with pytest.raises(ValueError):
        CredentialCipher(short)


def test_decrypt_rejects_tampered_ciphertext() -> None:
    cipher = CredentialCipher(_key())
    ct, nonce = cipher.encrypt("secret")
    tampered = bytearray(ct)
    tampered[0] ^= 0xFF
    with pytest.raises(ValueError):
        cipher.decrypt(bytes(tampered), nonce)


def test_decrypt_rejects_wrong_nonce_length() -> None:
    cipher = CredentialCipher(_key())
    ct, _ = cipher.encrypt("x")
    with pytest.raises(ValueError):
        cipher.decrypt(ct, b"\x00" * 8)


def test_encrypt_rejects_non_string() -> None:
    cipher = CredentialCipher(_key())
    with pytest.raises(TypeError):
        cipher.encrypt(b"bytes")  # type: ignore[arg-type]


def test_fingerprint_rejects_non_string() -> None:
    cipher = CredentialCipher(_key())
    with pytest.raises(TypeError):
        cipher.fingerprint(b"bytes")  # type: ignore[arg-type]
