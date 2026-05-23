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
