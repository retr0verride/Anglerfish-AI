"""Tests for :mod:`anglerfish.fingerprint.hashes`."""

from __future__ import annotations

import hashlib

from anglerfish.fingerprint.hashes import (
    compute_hassh,
    compute_hassh_string,
    compute_ja3,
    compute_ja3_string,
)


def test_ja3_string_format() -> None:
    s = compute_ja3_string(771, [4865, 4866], [0, 23], [29, 23], [0])
    assert s == "771,4865-4866,0-23,29-23,0"


def test_ja3_hash_matches_md5_of_canonical_string() -> None:
    canonical = "771,4865-4866,0-23,29-23,0"
    expected = hashlib.md5(canonical.encode("ascii"), usedforsecurity=False).hexdigest()
    actual = compute_ja3(771, [4865, 4866], [0, 23], [29, 23], [0])
    assert actual == expected
    assert len(actual) == 32
    assert all(c in "0123456789abcdef" for c in actual)


def test_ja3_empty_lists_render_empty_segments() -> None:
    s = compute_ja3_string(769, [], [], [], [])
    assert s == "769,,,,"


def test_hassh_string_format() -> None:
    s = compute_hassh_string(
        ["curve25519-sha256"],
        ["aes256-gcm@openssh.com", "chacha20-poly1305@openssh.com"],
        ["hmac-sha2-256-etm@openssh.com"],
        ["none", "zlib@openssh.com"],
    )
    assert s == (
        "curve25519-sha256;"
        "aes256-gcm@openssh.com,chacha20-poly1305@openssh.com;"
        "hmac-sha2-256-etm@openssh.com;"
        "none,zlib@openssh.com"
    )


def test_hassh_hash_matches_md5() -> None:
    canonical = compute_hassh_string(["a", "b"], ["c"], ["d"], ["e"])
    actual = compute_hassh(["a", "b"], ["c"], ["d"], ["e"])
    expected = hashlib.md5(canonical.encode("ascii"), usedforsecurity=False).hexdigest()
    assert actual == expected


# ---------------------------------------------------------------------------
# Hardening against attacker-controlled algorithm names (audit H3)
# ---------------------------------------------------------------------------


def test_hassh_non_ascii_name_does_not_crash() -> None:
    """A malicious client can offer a non-ASCII algorithm name.

    The name-lists are fully attacker-controlled in a honeypot, and the
    hash is computed inside the post-kex hook in begin_auth. A non-ASCII
    byte must not raise UnicodeEncodeError (which would crash that path).
    """
    h = compute_hassh(["aesé-x"], ["m"], [], [])
    assert len(h) == 32
    assert all(c in "0123456789abcdef" for c in h)


def test_hassh_strips_field_separators_from_names() -> None:
    """``,`` / ``;`` inside an algorithm name cannot inject a field boundary.

    A crafted name containing the record (``;``) or field (``,``)
    separators is sanitised so it cannot shift the canonical-string
    layout and blur one attacker's fingerprint into another's.
    """
    s = compute_hassh_string(["a;b,c"], ["x"], [], [])
    # The only ``;`` are the three real field separators; the name's
    # injected separators are gone.
    assert s.count(";") == 3
    assert s.split(";")[0] == "abc"
