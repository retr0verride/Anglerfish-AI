"""Tests for :class:`anglerfish.credentials.CredentialCipher`."""

from __future__ import annotations

import base64

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

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


def test_decrypt_rejects_non_utf8_plaintext() -> None:
    # Callers that skip mixed-key rows rely on decrypt() raising ValueError
    # when the GCM tag verifies but the bytes are not UTF-8. Forge that case
    # by encrypting raw non-UTF-8 bytes with the same key (a tag-valid
    # ciphertext that cannot decode).
    raw = base64.b64decode(_key())
    nonce = b"\x01" * 12
    bad_ct = AESGCM(raw).encrypt(nonce, b"\xff\xfe\xfd", None)
    cipher = CredentialCipher(_key())
    with pytest.raises(ValueError, match="not valid UTF-8"):
        cipher.decrypt(bad_ct, nonce)


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


def test_encrypt_decrypt_round_trips_lone_surrogate() -> None:
    """Mythos L4: a captured value with a lone UTF-16 surrogate must not
    crash encrypt and must round-trip back unchanged."""
    import base64

    from anglerfish.credentials.crypto import CredentialCipher

    cipher = CredentialCipher(base64.b64encode(b"k" * 32).decode("ascii"))
    value = "\ud800broken-surrogate"
    ct, nonce = cipher.encrypt(value)
    assert cipher.decrypt(ct, nonce) == value
