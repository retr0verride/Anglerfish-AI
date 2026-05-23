"""Tests for :mod:`anglerfish.wizard.sshkey`."""

from __future__ import annotations

import base64

import pytest

from anglerfish.wizard.sshkey import SshPubKey, SshPubKeyError, parse_ssh_pubkey

_ED25519_BLOB = base64.b64encode(b"\x00\x00\x00\x0bssh-ed25519" + b"\x00" * 40).decode()
_RSA_BLOB = base64.b64encode(b"\x00\x00\x00\x07ssh-rsa" + b"\x00" * 256).decode()


def test_parses_ed25519_key() -> None:
    line = f"ssh-ed25519 {_ED25519_BLOB} alice@laptop"
    key = parse_ssh_pubkey(line)
    assert isinstance(key, SshPubKey)
    assert key.key_type == "ssh-ed25519"
    assert key.blob == _ED25519_BLOB
    assert key.comment == "alice@laptop"


def test_parses_rsa_key() -> None:
    line = f"ssh-rsa {_RSA_BLOB} ops"
    key = parse_ssh_pubkey(line)
    assert key.key_type == "ssh-rsa"


def test_parses_without_comment() -> None:
    key = parse_ssh_pubkey(f"ssh-ed25519 {_ED25519_BLOB}")
    assert key.comment is None


def test_canonical_round_trip() -> None:
    raw = f"ssh-ed25519 {_ED25519_BLOB} ops "
    parsed = parse_ssh_pubkey(raw)
    rendered = parsed.to_authorized_keys_line()
    re_parsed = parse_ssh_pubkey(rendered)
    assert re_parsed == parsed


def test_rejects_empty() -> None:
    with pytest.raises(SshPubKeyError, match="empty"):
        parse_ssh_pubkey("")


def test_rejects_non_string() -> None:
    with pytest.raises(SshPubKeyError):
        parse_ssh_pubkey(b"ssh-ed25519 ...")  # type: ignore[arg-type]


def test_rejects_multiline() -> None:
    with pytest.raises(SshPubKeyError, match="single line"):
        parse_ssh_pubkey(f"ssh-ed25519 {_ED25519_BLOB}\nattacker-key")


def test_rejects_carriage_return() -> None:
    with pytest.raises(SshPubKeyError, match="single line"):
        parse_ssh_pubkey(f"ssh-ed25519 {_ED25519_BLOB}\r")


def test_rejects_single_token() -> None:
    with pytest.raises(SshPubKeyError, match="at least"):
        parse_ssh_pubkey("ssh-ed25519")


def test_rejects_unsupported_type() -> None:
    with pytest.raises(SshPubKeyError, match="unsupported"):
        parse_ssh_pubkey(f"ssh-dss {_ED25519_BLOB} legacy")


def test_rejects_invalid_base64() -> None:
    with pytest.raises(SshPubKeyError, match="base64"):
        parse_ssh_pubkey("ssh-ed25519 not!base64!")


def test_rejects_too_short_blob() -> None:
    short_blob = base64.b64encode(b"\x00" * 4).decode()  # 4 bytes
    with pytest.raises(SshPubKeyError, match="out of range"):
        parse_ssh_pubkey(f"ssh-ed25519 {short_blob}")


def test_rejects_too_long_blob() -> None:
    big_blob = base64.b64encode(b"\x00" * 9000).decode()
    with pytest.raises(SshPubKeyError, match="out of range"):
        parse_ssh_pubkey(f"ssh-ed25519 {big_blob}")


def test_rejects_control_chars_in_comment() -> None:
    with pytest.raises(SshPubKeyError, match="control"):
        parse_ssh_pubkey(f"ssh-ed25519 {_ED25519_BLOB} bad\x07comment")


def test_rejects_overlong_comment() -> None:
    long_comment = "x" * 300
    with pytest.raises(SshPubKeyError, match="comment too long"):
        parse_ssh_pubkey(f"ssh-ed25519 {_ED25519_BLOB} {long_comment}")


def test_accepts_ecdsa() -> None:
    blob = base64.b64encode(b"\x00" * 256).decode()
    key = parse_ssh_pubkey(f"ecdsa-sha2-nistp256 {blob}")
    assert key.key_type == "ecdsa-sha2-nistp256"
