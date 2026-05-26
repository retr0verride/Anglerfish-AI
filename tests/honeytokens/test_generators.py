"""Tests for the Stage 11 slice 11.1 :class:`HoneytokenGenerator`."""

from __future__ import annotations

import re
from datetime import UTC, datetime
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519

from anglerfish.honeytokens import HoneytokenGenerator, new_lookup_id
from anglerfish.honeytokens.schema import Honeytoken


def _fixed_clock(when: datetime):  # type: ignore[no-untyped-def]
    def _clock() -> datetime:
        return when

    return _clock


# ---------------------------------------------------------------------------
# new_lookup_id format
# ---------------------------------------------------------------------------


def test_new_lookup_id_matches_aws_access_key_alphabet() -> None:
    """16 chars of RFC 4648 base32 - same alphabet AWS uses post-AKIA."""
    for _ in range(50):
        lookup_id = new_lookup_id()
        assert re.match(r"^[A-Z2-7]{16}$", lookup_id), lookup_id


def test_new_lookup_id_is_random_per_call() -> None:
    """Two calls must produce different IDs (probabilistic, ~80 bits)."""
    samples = {new_lookup_id() for _ in range(20)}
    assert len(samples) == 20


# ---------------------------------------------------------------------------
# AWS generator
# ---------------------------------------------------------------------------


def test_generate_aws_payload_has_canonical_ini_shape() -> None:
    gen = HoneytokenGenerator(callback_base_url="https://honey.example.com")
    token = gen.generate_aws(source_ip="203.0.113.7")
    assert token.kind == "aws"
    assert "[default]" in token.payload
    assert "aws_access_key_id = AKIA" in token.payload
    assert "aws_secret_access_key" in token.payload
    assert "region = us-east-1" in token.payload


def test_generate_aws_access_key_id_carries_lookup_id() -> None:
    gen = HoneytokenGenerator(callback_base_url="https://honey.example.com")
    token = gen.generate_aws(source_ip="203.0.113.7")
    expected_line = f"aws_access_key_id = AKIA{token.id}"
    assert expected_line in token.payload


def test_generate_aws_secret_is_forty_chars_aws_alphabet() -> None:
    gen = HoneytokenGenerator(callback_base_url="https://honey.example.com")
    token = gen.generate_aws(source_ip="203.0.113.7")
    match = re.search(r"aws_secret_access_key = (\S+)", token.payload)
    assert match is not None
    secret = match.group(1)
    assert len(secret) == 40
    assert re.match(r"^[A-Za-z0-9/+]+$", secret)


def test_generate_aws_callback_url_embeds_lookup_id() -> None:
    gen = HoneytokenGenerator(callback_base_url="https://honey.example.com")
    token = gen.generate_aws(source_ip="203.0.113.7")
    assert token.callback_url == f"https://honey.example.com/cb/{token.id}"


def test_generate_aws_strips_trailing_slash_in_callback_base_url() -> None:
    gen = HoneytokenGenerator(callback_base_url="https://honey.example.com/")
    token = gen.generate_aws(source_ip="203.0.113.7")
    assert "https://honey.example.com/cb/" in token.callback_url
    assert "//cb/" not in token.callback_url


def test_generate_aws_default_placed_at_is_root_aws_credentials() -> None:
    gen = HoneytokenGenerator(callback_base_url="https://honey.example.com")
    token = gen.generate_aws(source_ip="203.0.113.7")
    assert token.placed_at == "/root/.aws/credentials"


def test_generate_aws_respects_custom_placed_at() -> None:
    gen = HoneytokenGenerator(callback_base_url="https://honey.example.com")
    token = gen.generate_aws(
        source_ip="203.0.113.7",
        placed_at="/home/alice/.aws/credentials",
    )
    assert token.placed_at == "/home/alice/.aws/credentials"


def test_generate_aws_provenance_round_trips() -> None:
    gen = HoneytokenGenerator(callback_base_url="https://honey.example.com")
    sid = uuid4()
    token = gen.generate_aws(source_ip="203.0.113.7", session_id=sid)
    assert token.source_ip == "203.0.113.7"
    assert token.session_id == sid


def test_generate_aws_static_base_when_no_provenance() -> None:
    gen = HoneytokenGenerator(callback_base_url="https://honey.example.com")
    token = gen.generate_aws()
    assert token.source_ip is None
    assert token.session_id is None
    assert token.is_static_base()


# ---------------------------------------------------------------------------
# SSH generator
# ---------------------------------------------------------------------------


def test_generate_ssh_payload_includes_openssh_private_key() -> None:
    gen = HoneytokenGenerator(callback_base_url="https://honey.example.com")
    token = gen.generate_ssh(source_ip="203.0.113.7")
    assert token.kind == "ssh_key"
    assert "-----BEGIN OPENSSH PRIVATE KEY-----" in token.payload
    assert "-----END OPENSSH PRIVATE KEY-----" in token.payload


def test_generate_ssh_payload_embeds_public_key_comment_header() -> None:
    """The lookup ID rides in the public-key comment for paste/Shodan grep."""
    gen = HoneytokenGenerator(callback_base_url="https://honey.example.com")
    token = gen.generate_ssh(source_ip="203.0.113.7")
    assert f"honeytoken-{token.id}" in token.payload
    assert "ssh-ed25519" in token.payload


def test_generate_ssh_default_placed_at_is_root_id_rsa() -> None:
    gen = HoneytokenGenerator(callback_base_url="https://honey.example.com")
    token = gen.generate_ssh(source_ip="203.0.113.7")
    assert token.placed_at == "/root/.ssh/id_rsa"


def test_generate_ssh_callback_url_embeds_lookup_id() -> None:
    gen = HoneytokenGenerator(callback_base_url="https://honey.example.com")
    token = gen.generate_ssh(source_ip="203.0.113.7")
    assert token.callback_url == f"https://honey.example.com/cb/{token.id}"


# ---------------------------------------------------------------------------
# Deterministic generation via id + clock + key factories
# ---------------------------------------------------------------------------


def test_generators_use_provided_id_factory() -> None:
    fixed_id = "AAAAAAAAAAAAAAAA"  # 16 base32 chars
    gen = HoneytokenGenerator(
        callback_base_url="https://honey.example.com",
        id_factory=lambda: fixed_id,
    )
    aws = gen.generate_aws()
    ssh = gen.generate_ssh()
    assert aws.id == fixed_id
    assert ssh.id == fixed_id


def test_generators_use_provided_clock() -> None:
    when = datetime(2026, 5, 26, 12, 0, tzinfo=UTC)
    gen = HoneytokenGenerator(
        callback_base_url="https://honey.example.com",
        clock=_fixed_clock(when),
    )
    aws = gen.generate_aws()
    assert aws.created_at == when


def test_aws_secret_factory_can_be_injected() -> None:
    """Allow tests to pin the secret for stable assertions."""
    gen = HoneytokenGenerator(
        callback_base_url="https://honey.example.com",
        secret_factory=lambda: "P" * 40,
    )
    aws = gen.generate_aws()
    assert "P" * 40 in aws.payload


def test_ssh_key_factory_can_be_injected() -> None:
    """A custom ssh_key_factory routes through generate_ssh.

    Two outputs from the same fixed key share the same public-key
    bytes (the encoded public point is deterministic); OpenSSH
    private-key PEM is NOT byte-identical because the OpenSSH
    format embeds random ``checkint`` sanity-check uint32s on
    every serialization, so we only assert the public-key
    fingerprint matches.
    """
    fixed_key = ed25519.Ed25519PrivateKey.generate()
    gen = HoneytokenGenerator(
        callback_base_url="https://honey.example.com",
        ssh_key_factory=lambda: fixed_key,
    )
    a = gen.generate_ssh()
    b = gen.generate_ssh()
    # Both payloads contain the same ssh-ed25519 public-key bytes
    # (the header line embeds them); pull out the AAA... portion
    # and compare.
    a_pub = re.search(r"ssh-ed25519 (\S+)", a.payload)
    b_pub = re.search(r"ssh-ed25519 (\S+)", b.payload)
    assert a_pub is not None
    assert b_pub is not None
    assert a_pub.group(1) == b_pub.group(1)


# ---------------------------------------------------------------------------
# Constructor guards
# ---------------------------------------------------------------------------


def test_constructor_rejects_empty_callback_base_url() -> None:
    with pytest.raises(ValueError, match="callback_base_url"):
        HoneytokenGenerator(callback_base_url="")


# ---------------------------------------------------------------------------
# Honeytoken schema validation
# ---------------------------------------------------------------------------


def test_honeytoken_rejects_malformed_id() -> None:
    """The 16-char base32 pattern is pinned at the Pydantic layer."""
    with pytest.raises(ValueError, match=r"too_short|string_pattern_mismatch|pattern"):
        Honeytoken(
            id="not-a-valid-id",
            kind="aws",
            payload="x",
            callback_url="https://x/cb/x",
            placed_at="/root/.aws/credentials",
            created_at=datetime(2026, 5, 26, tzinfo=UTC),
        )
    # Right length, wrong alphabet (lowercase + numeric outside base32).
    with pytest.raises(ValueError, match=r"string_pattern_mismatch|pattern"):
        Honeytoken(
            id="a" * 16,
            kind="aws",
            payload="x",
            callback_url="https://x/cb/x",
            placed_at="/root/.aws/credentials",
            created_at=datetime(2026, 5, 26, tzinfo=UTC),
        )


def test_honeytoken_is_static_base_helper() -> None:
    token = Honeytoken(
        id="A" * 16,
        kind="aws",
        payload="x",
        callback_url="https://x/cb/x",
        placed_at="/root/.aws/credentials",
        created_at=datetime(2026, 5, 26, tzinfo=UTC),
    )
    assert token.is_static_base() is True
    sid = uuid4()
    other = token.model_copy(update={"source_ip": "1.1.1.1", "session_id": sid})
    assert other.is_static_base() is False
