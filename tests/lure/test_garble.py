"""Unit tests for the Stage 12 counter-deception garble primitives."""

from __future__ import annotations

from uuid import UUID, uuid4

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from anglerfish.lure.garble import GarbleKind, garble, infer_kind

_SID = UUID("12345678-1234-5678-1234-567812345678")


def _real_openssh_key() -> str:
    key = ed25519.Ed25519PrivateKey.generate()
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.OpenSSH,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return pem.decode("ascii")


# ---------------------------------------------------------------------------
# Kind inference
# ---------------------------------------------------------------------------


def test_infer_kind_pem_by_name() -> None:
    assert infer_kind("/root/.ssh/id_rsa", "anything") is GarbleKind.PEM
    assert infer_kind("/home/x/.ssh/id_ed25519", "x") is GarbleKind.PEM


def test_infer_kind_pem_by_content_armor() -> None:
    assert infer_kind("/tmp/whatever", "-----BEGIN OPENSSH PRIVATE KEY-----\n") is GarbleKind.PEM


def test_infer_kind_aws() -> None:
    assert infer_kind("/root/.aws/credentials", "[default]") is GarbleKind.AWS
    assert infer_kind("/home/u/.aws/config", "[profile x]") is GarbleKind.AWS


def test_infer_kind_default_fallback() -> None:
    assert infer_kind("/etc/app.conf", "key=value\n") is GarbleKind.DEFAULT


# ---------------------------------------------------------------------------
# PEM garble
# ---------------------------------------------------------------------------


def test_pem_garble_preserves_armor_and_breaks_parse() -> None:
    original = _real_openssh_key()
    result = garble(original, session_id=_SID, path="/root/.ssh/id_ed25519")
    assert result.kind is GarbleKind.PEM
    assert result.content.startswith("-----BEGIN OPENSSH PRIVATE KEY-----")
    assert "-----END OPENSSH PRIVATE KEY-----" in result.content
    assert result.content != original
    # The corrupted body must no longer load as a valid key. Any parse
    # failure is the success case here, so a broad catch is intentional.
    try:
        serialization.load_ssh_private_key(result.content.encode("ascii"), password=None)
    except Exception:  # noqa: BLE001 - any parse failure proves corruption
        parsed = False
    else:
        parsed = True
    assert parsed is False


def test_pem_garble_char_counts_recorded() -> None:
    original = _real_openssh_key()
    result = garble(original, session_id=_SID, path="/root/.ssh/id_ed25519")
    assert result.original_chars == len(original)
    assert result.garbled_chars == len(result.content)


# ---------------------------------------------------------------------------
# AWS garble
# ---------------------------------------------------------------------------


def test_aws_garble_preserves_access_key_id_mangles_secret() -> None:
    creds = (
        "[default]\n"
        "aws_access_key_id = AKIAIOSFODNN7EXAMPLE\n"
        "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
        "region = us-east-1\n"
    )
    result = garble(creds, session_id=_SID, path="/root/.aws/credentials")
    assert result.kind is GarbleKind.AWS
    assert "AKIAIOSFODNN7EXAMPLE" in result.content  # AKIA prefix preserved
    assert "[default]" in result.content
    assert "region = us-east-1" in result.content
    assert "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" not in result.content


def test_aws_garble_without_secret_line_falls_back_to_default() -> None:
    # An .aws/config with no secret-access-key still gets corrupted.
    content = "[profile work]\nregion = eu-west-1\noutput = json\n" * 100
    result = garble(content, session_id=_SID, path="/root/.aws/config")
    assert result.kind is GarbleKind.AWS
    assert result.content != content


# ---------------------------------------------------------------------------
# Default-text garble
# ---------------------------------------------------------------------------


def test_default_garble_preserves_prefix_and_length() -> None:
    content = "line of plausible config\n" * 400  # well over the 4 KB prefix
    result = garble(content, session_id=_SID, path="/etc/myapp.conf")
    assert result.kind is GarbleKind.DEFAULT
    assert result.content != content
    assert len(result.content) == len(content)
    # The 4 KB prefix survives so `head` shows real content.
    assert result.content[:4096] == content[:4096]


def test_default_garble_short_content_still_corrupts() -> None:
    content = "short\n"
    result = garble(content, session_id=_SID, path="/etc/x.conf")
    assert result.content != content


# ---------------------------------------------------------------------------
# Determinism
# ---------------------------------------------------------------------------


def test_same_session_and_path_is_deterministic() -> None:
    content = _real_openssh_key()
    a = garble(content, session_id=_SID, path="/root/.ssh/id_ed25519")
    b = garble(content, session_id=_SID, path="/root/.ssh/id_ed25519")
    assert a.content == b.content


def test_different_session_differs() -> None:
    content = _real_openssh_key()
    a = garble(content, session_id=_SID, path="/root/.ssh/id_ed25519")
    b = garble(content, session_id=uuid4(), path="/root/.ssh/id_ed25519")
    assert a.content != b.content


def test_different_path_differs() -> None:
    content = "the same content at two paths\n" * 300
    a = garble(content, session_id=_SID, path="/etc/a.conf")
    b = garble(content, session_id=_SID, path="/etc/b.conf")
    assert a.content != b.content
