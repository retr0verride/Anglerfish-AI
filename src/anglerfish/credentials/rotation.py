"""Rotate the credentials encryption key.

Decrypts every row in the SQLite store with the current cipher,
re-encrypts under a new cipher, and atomically swaps the database
file with the new one. The old database is preserved as
``<path>.bak`` so a failed rotation can be reverted.

This is **synchronous and offline** by design — the bridge and
dashboard must be stopped before invoking it. Rotation while the
store is being written would risk losing concurrent writes. The CLI
command (``anglerfish credentials rotate-key``) refuses to proceed
when it can detect a live SQLite WAL.
"""

from __future__ import annotations

import logging
import shutil
import sqlite3
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path

from anglerfish.credentials.crypto import CredentialCipher

__all__ = ["RotationError", "RotationResult", "rotate_key"]


_logger = logging.getLogger(__name__)


_SCHEMA = """
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS attempts (
    id              INTEGER PRIMARY KEY,
    source_ip       TEXT NOT NULL,
    session_id      TEXT NOT NULL,
    username_ct     BLOB NOT NULL,
    username_nonce  BLOB NOT NULL,
    password_ct     BLOB NOT NULL,
    password_nonce  BLOB NOT NULL,
    username_fp     BLOB NOT NULL,
    password_fp     BLOB NOT NULL,
    first_seen      TEXT NOT NULL,
    last_seen       TEXT NOT NULL,
    attempt_count   INTEGER NOT NULL DEFAULT 1
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_attempts_unique
    ON attempts(source_ip, username_fp, password_fp);
CREATE INDEX IF NOT EXISTS idx_attempts_last_seen ON attempts(last_seen);
CREATE INDEX IF NOT EXISTS idx_attempts_source_ip ON attempts(source_ip);
"""


class RotationError(RuntimeError):
    """Raised when key rotation could not complete safely."""


@dataclass(frozen=True)
class RotationResult:
    """Outcome of a successful rotation."""

    rows_rotated: int
    rows_skipped: int
    backup_path: Path
    new_path: Path


def rotate_key(
    *,
    db_path: Path,
    old_cipher: CredentialCipher,
    new_cipher: CredentialCipher,
) -> RotationResult:
    """Re-encrypt every row in ``db_path`` from ``old_cipher`` to ``new_cipher``.

    Strategy:

    1. Open the existing database read-only.
    2. Create a new database next to it (``<path>.new``).
    3. For each row in ``attempts``: decrypt with ``old_cipher``,
       re-encrypt with ``new_cipher``, insert into the new DB.
    4. Move the old DB aside as ``<path>.bak`` and rename the new
       DB into place.

    Rows whose ciphertext cannot be decrypted with ``old_cipher`` are
    skipped and counted — this lets operators recover from a partial
    earlier rotation that left mixed-key rows.

    Raises:
        RotationError: if the DB is missing, the new-DB path is
            already in use, or the swap step fails.
    """
    if not db_path.exists():
        raise RotationError(f"credentials database not found at {db_path}")

    new_path = db_path.with_suffix(db_path.suffix + ".new")
    if new_path.exists():
        raise RotationError(
            f"rotation work file already exists at {new_path}; remove it first",
        )

    backup_path = db_path.with_suffix(db_path.suffix + ".bak")
    if backup_path.exists():
        raise RotationError(
            f"backup file already exists at {backup_path}; remove it first",
        )

    rows_rotated = 0
    rows_skipped = 0

    try:
        with (
            closing(sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)) as old_conn,
            closing(sqlite3.connect(str(new_path))) as new_conn,
        ):
            new_conn.executescript(_SCHEMA)
            cursor = old_conn.execute(
                "SELECT source_ip, session_id, username_ct, username_nonce, "
                "password_ct, password_nonce, first_seen, last_seen, attempt_count "
                "FROM attempts",
            )
            for row in cursor:
                (
                    source_ip,
                    session_id,
                    ct_u,
                    nonce_u,
                    ct_p,
                    nonce_p,
                    first_seen,
                    last_seen,
                    attempt_count,
                ) = row
                try:
                    username = old_cipher.decrypt(ct_u, nonce_u)
                    password = old_cipher.decrypt(ct_p, nonce_p)
                except ValueError as exc:
                    _logger.warning(
                        "rotation: skipping row source_ip=%s: %s",
                        source_ip,
                        exc,
                    )
                    rows_skipped += 1
                    continue
                new_ct_u, new_nonce_u = new_cipher.encrypt(username)
                new_ct_p, new_nonce_p = new_cipher.encrypt(password)
                new_fp_u = new_cipher.fingerprint(username)
                new_fp_p = new_cipher.fingerprint(password)
                new_conn.execute(
                    "INSERT INTO attempts ("
                    "source_ip, session_id, "
                    "username_ct, username_nonce, password_ct, password_nonce, "
                    "username_fp, password_fp, "
                    "first_seen, last_seen, attempt_count"
                    ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        source_ip,
                        session_id,
                        new_ct_u,
                        new_nonce_u,
                        new_ct_p,
                        new_nonce_p,
                        new_fp_u,
                        new_fp_p,
                        first_seen,
                        last_seen,
                        attempt_count,
                    ),
                )
                rows_rotated += 1
            new_conn.commit()
    except sqlite3.Error as exc:
        # Clean up the half-built new DB on any failure.
        if new_path.exists():
            new_path.unlink()
        raise RotationError(f"rotation failed: {exc}") from exc

    # Atomic-ish swap. POSIX rename(2) is atomic on the same filesystem,
    # but two renames in a row aren't transactional — a crash between them
    # leaves db_path missing but recoverable from backup_path.
    try:
        shutil.move(str(db_path), str(backup_path))
        shutil.move(str(new_path), str(db_path))
    except OSError as exc:
        raise RotationError(f"rotation swap failed: {exc}") from exc

    _logger.info(
        "credentials rotation: rotated=%d skipped=%d backup=%s",
        rows_rotated,
        rows_skipped,
        backup_path,
    )
    return RotationResult(
        rows_rotated=rows_rotated,
        rows_skipped=rows_skipped,
        backup_path=backup_path,
        new_path=db_path,
    )
