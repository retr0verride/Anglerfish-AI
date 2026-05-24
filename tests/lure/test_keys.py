"""Tests for :mod:`anglerfish.lure.keys`."""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from anglerfish.lure.keys import (
    ED25519_KEY_FILENAME,
    RSA_KEY_FILENAME,
    HostKeyPermissionError,
    ensure_host_keys,
    load_host_keys,
    validate_key_permissions,
)

_IS_POSIX = os.name != "nt"


def test_ensure_creates_both_keys_with_correct_modes(tmp_path: Path) -> None:
    paths = ensure_host_keys(tmp_path / "keys")
    assert paths.rsa.name == RSA_KEY_FILENAME
    assert paths.ed25519.name == ED25519_KEY_FILENAME
    assert paths.rsa.exists()
    assert paths.ed25519.exists()
    rsa_bytes = paths.rsa.read_bytes()
    ed_bytes = paths.ed25519.read_bytes()
    # OpenSSH PEM private keys start with this marker.
    assert rsa_bytes.startswith(b"-----BEGIN OPENSSH PRIVATE KEY-----")
    assert ed_bytes.startswith(b"-----BEGIN OPENSSH PRIVATE KEY-----")
    if _IS_POSIX:
        assert stat.S_IMODE(paths.rsa.stat().st_mode) == 0o600
        assert stat.S_IMODE(paths.ed25519.stat().st_mode) == 0o600


def test_ensure_is_no_op_when_keys_present(tmp_path: Path) -> None:
    paths = ensure_host_keys(tmp_path / "keys")
    rsa_before = paths.rsa.read_bytes()
    ed_before = paths.ed25519.read_bytes()
    paths2 = ensure_host_keys(tmp_path / "keys")
    assert paths == paths2
    assert paths.rsa.read_bytes() == rsa_before
    assert paths.ed25519.read_bytes() == ed_before


def test_load_returns_pem_bytes(tmp_path: Path) -> None:
    ensure_host_keys(tmp_path / "keys")
    rsa_pem, ed_pem = load_host_keys(tmp_path / "keys")
    assert rsa_pem.startswith(b"-----BEGIN OPENSSH PRIVATE KEY-----")
    assert ed_pem.startswith(b"-----BEGIN OPENSSH PRIVATE KEY-----")


def test_validate_rejects_missing_directory(tmp_path: Path) -> None:
    with pytest.raises(HostKeyPermissionError, match="does not exist"):
        validate_key_permissions(tmp_path / "nope")


def test_validate_rejects_missing_rsa_key(tmp_path: Path) -> None:
    ensure_host_keys(tmp_path / "keys")
    (tmp_path / "keys" / RSA_KEY_FILENAME).unlink()
    with pytest.raises(HostKeyPermissionError, match="missing RSA"):
        validate_key_permissions(tmp_path / "keys")


def test_validate_rejects_missing_ed25519_key(tmp_path: Path) -> None:
    ensure_host_keys(tmp_path / "keys")
    (tmp_path / "keys" / ED25519_KEY_FILENAME).unlink()
    with pytest.raises(HostKeyPermissionError, match="missing Ed25519"):
        validate_key_permissions(tmp_path / "keys")


@pytest.mark.skipif(not _IS_POSIX, reason="POSIX permission model only")
def test_validate_rejects_world_readable_key(tmp_path: Path) -> None:
    paths = ensure_host_keys(tmp_path / "keys")
    paths.rsa.chmod(0o644)
    with pytest.raises(HostKeyPermissionError, match="too permissive"):
        validate_key_permissions(tmp_path / "keys")


@pytest.mark.skipif(not _IS_POSIX, reason="POSIX permission model only")
def test_validate_rejects_group_readable_key(tmp_path: Path) -> None:
    paths = ensure_host_keys(tmp_path / "keys")
    paths.ed25519.chmod(0o640)
    with pytest.raises(HostKeyPermissionError, match="too permissive"):
        validate_key_permissions(tmp_path / "keys")


@pytest.mark.skipif(not _IS_POSIX, reason="POSIX permission model only")
def test_validate_rejects_group_readable_directory(tmp_path: Path) -> None:
    ensure_host_keys(tmp_path / "keys")
    (tmp_path / "keys").chmod(0o755)
    with pytest.raises(HostKeyPermissionError, match="directory"):
        validate_key_permissions(tmp_path / "keys")


def test_validate_accepts_owner_only_layout(tmp_path: Path) -> None:
    paths = ensure_host_keys(tmp_path / "keys")
    resolved = validate_key_permissions(tmp_path / "keys")
    assert resolved == paths


@pytest.mark.skipif(_IS_POSIX, reason="Windows-only fallback path")
def test_validate_skips_mode_check_on_windows(tmp_path: Path) -> None:
    # On nt the function still verifies file existence but does not
    # check mode bits; document the fallback path.
    ensure_host_keys(tmp_path / "keys")
    validate_key_permissions(tmp_path / "keys")


def test_load_propagates_permission_error(tmp_path: Path) -> None:
    if not _IS_POSIX:
        pytest.skip("POSIX permission model only")
    paths = ensure_host_keys(tmp_path / "keys")
    paths.rsa.chmod(0o666)
    with pytest.raises(HostKeyPermissionError):
        load_host_keys(tmp_path / "keys")


def test_module_constants_export_filenames() -> None:
    assert RSA_KEY_FILENAME == "ssh_host_rsa_key"
    assert ED25519_KEY_FILENAME == "ssh_host_ed25519_key"


def test_keys_module_does_not_import_asyncssh() -> None:
    """``keys.py`` must stand on cryptography alone.

    The wizard generates host keys before asyncssh is necessarily
    importable, so the source of ``lure/keys.py`` should not contain
    any ``import asyncssh`` / ``from asyncssh`` statement. The sys
    .modules check used in Stage 2A is no longer reliable because the
    Stage 2B server module legitimately imports asyncssh and gets
    loaded by sibling tests, polluting the module set.
    """
    import anglerfish.lure.keys as keys_mod

    source = Path(keys_mod.__file__).read_text(encoding="utf-8")
    # Source-level grep, not symbol-table introspection.
    for line in source.splitlines():
        stripped = line.lstrip()
        assert not stripped.startswith("import asyncssh"), line
        assert not stripped.startswith("from asyncssh"), line
