"""SSH host-key generation, loading, and permission validation.

The lure presents both RSA 4096 and Ed25519 host keys so legacy and
modern clients can negotiate. Keys are generated at first boot via the
wizard and persisted under :attr:`LureConfig.host_key_dir`. The keys
themselves never live in the repo.

Key generation uses ``cryptography`` (already a runtime dependency
for the credentials AES-GCM cipher); the asyncssh server in
:mod:`anglerfish.lure.server` consumes the PEM bytes returned by
:func:`load_host_keys` via ``asyncssh.import_private_key``.
"""

from __future__ import annotations

import contextlib
import os
import stat
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa

__all__ = [
    "ED25519_KEY_FILENAME",
    "RSA_KEY_FILENAME",
    "HostKeyPaths",
    "HostKeyPermissionError",
    "ensure_host_keys",
    "load_host_keys",
    "validate_key_permissions",
]


RSA_KEY_FILENAME = "ssh_host_rsa_key"
ED25519_KEY_FILENAME = "ssh_host_ed25519_key"

_RSA_KEY_SIZE_BITS = 4096
_PUBLIC_EXPONENT = 65537

# Mode bits that disqualify a key. Anything outside owner-read-write
# (mode 0600) or stricter is rejected, matching OpenSSH StrictModes.
_FORBIDDEN_KEY_MODE_MASK = 0o077

# Mode bits that disqualify the directory. 0700 or stricter only.
_FORBIDDEN_DIR_MODE_MASK = 0o077


class HostKeyPermissionError(Exception):
    """Raised when key file or directory permissions are too loose.

    The lure refuses to load keys (or refuses to start) in this state,
    same posture as ``sshd``'s ``StrictModes yes``.
    """


@dataclass(frozen=True)
class HostKeyPaths:
    """Filesystem locations of the lure's host keys."""

    rsa: Path
    ed25519: Path


def _paths_for(directory: Path) -> HostKeyPaths:
    return HostKeyPaths(
        rsa=directory / RSA_KEY_FILENAME,
        ed25519=directory / ED25519_KEY_FILENAME,
    )


def ensure_host_keys(directory: Path) -> HostKeyPaths:
    """Generate the host keys if they do not already exist.

    Idempotent: existing keys are preserved untouched (lets operators
    pre-stage keys via configuration management without the wizard
    overwriting them). Newly generated keys are written with mode
    0600; the parent directory with mode 0700.
    """
    directory.mkdir(parents=True, exist_ok=True)
    with contextlib.suppress(OSError):
        # Best-effort on Windows where chmod is a no-op.
        os.chmod(directory, 0o700)

    paths = _paths_for(directory)
    if not paths.rsa.exists():
        _write_rsa_key(paths.rsa)
    if not paths.ed25519.exists():
        _write_ed25519_key(paths.ed25519)
    return paths


def _write_rsa_key(path: Path) -> None:
    key = rsa.generate_private_key(
        public_exponent=_PUBLIC_EXPONENT,
        key_size=_RSA_KEY_SIZE_BITS,
    )
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.OpenSSH,
        encryption_algorithm=serialization.NoEncryption(),
    )
    _write_key_bytes(path, pem)


def _write_ed25519_key(path: Path) -> None:
    key = ed25519.Ed25519PrivateKey.generate()
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.OpenSSH,
        encryption_algorithm=serialization.NoEncryption(),
    )
    _write_key_bytes(path, pem)


def _write_key_bytes(path: Path, data: bytes) -> None:
    # Write to a temp file in the same directory then rename, so a
    # crash mid-write does not leave a partial key. fd opened 0600.
    tmp = path.with_suffix(path.suffix + ".tmp")
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "wb") as fp:
            fp.write(data)
    except BaseException:
        # Catch BaseException so Ctrl-C (KeyboardInterrupt) mid-write
        # also unlinks the partial tmp file before re-raising.
        with contextlib.suppress(OSError):
            tmp.unlink()
        raise
    os.replace(str(tmp), str(path))
    with contextlib.suppress(OSError):
        os.chmod(path, 0o600)


def validate_key_permissions(directory: Path) -> HostKeyPaths:
    """Verify the directory and both key files are owner-only.

    Raises :class:`HostKeyPermissionError` if either the directory or
    either key file has group/world bits set, or if a key file is
    missing. Returns the resolved paths on success.

    On Windows the POSIX permission model does not apply; the function
    skips the mode check there (the equivalent ACL check would need a
    Windows-specific implementation that Stage 2A does not ship).
    """
    if not directory.is_dir():
        raise HostKeyPermissionError(
            f"host key directory {directory!s} does not exist or is not a directory",
        )

    paths = _paths_for(directory)
    if not paths.rsa.is_file():
        raise HostKeyPermissionError(f"missing RSA host key at {paths.rsa!s}")
    if not paths.ed25519.is_file():
        raise HostKeyPermissionError(f"missing Ed25519 host key at {paths.ed25519!s}")

    if os.name == "nt":
        return paths

    dir_mode = stat.S_IMODE(directory.stat().st_mode)
    if dir_mode & _FORBIDDEN_DIR_MODE_MASK:
        raise HostKeyPermissionError(
            f"host key directory {directory!s} mode {dir_mode:o} is too permissive "
            "(must be 0700 or stricter)",
        )

    for label, path in (("RSA", paths.rsa), ("Ed25519", paths.ed25519)):
        mode = stat.S_IMODE(path.stat().st_mode)
        if mode & _FORBIDDEN_KEY_MODE_MASK:
            raise HostKeyPermissionError(
                f"{label} host key {path!s} mode {mode:o} is too permissive "
                "(must be 0600 or stricter)",
            )

    return paths


def load_host_keys(directory: Path) -> tuple[bytes, bytes]:
    """Return the (rsa_pem, ed25519_pem) bytes after a permission check.

    The bytes are fed to ``asyncssh.import_private_key`` by the
    server module; this function returns raw PEM so the permission
    validation code stays testable without an asyncssh dependency.
    """
    paths = validate_key_permissions(directory)
    return paths.rsa.read_bytes(), paths.ed25519.read_bytes()
