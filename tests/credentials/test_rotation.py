"""Tests for the credentials-encryption-key rotation tool."""

from __future__ import annotations

import base64
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import pytest
from pydantic import SecretStr

from anglerfish.config.models import CredentialsConfig
from anglerfish.credentials import (
    CredentialCipher,
    CredentialStore,
    RotationError,
    rotate_key,
)


def _key(byte: int) -> str:
    return base64.b64encode(bytes([byte] * 32)).decode("ascii")


def _config(path: Path, key: str) -> CredentialsConfig:
    return CredentialsConfig(database_path=path, encryption_key=SecretStr(key))


async def _populate(store: CredentialStore, *, count: int) -> None:
    base_ts = datetime(2026, 5, 22, tzinfo=UTC)
    for i in range(count):
        await store.record_attempt(
            source_ip=f"203.0.113.{i % 254 + 1}",
            username=f"user{i}",
            password=f"pass{i}",
            session_id=uuid4(),
            timestamp=base_ts.replace(microsecond=i),
        )


async def test_round_trip_decryption(tmp_path: Path) -> None:
    db = tmp_path / "creds.db"
    old_key = _key(1)
    new_key = _key(2)

    async with CredentialStore(_config(db, old_key)) as store:
        await _populate(store, count=5)
        before = await store.query(limit=100)

    result = rotate_key(
        db_path=db,
        old_cipher=CredentialCipher(old_key),
        new_cipher=CredentialCipher(new_key),
    )
    assert result.rows_rotated == 5
    assert result.rows_skipped == 0
    assert result.backup_path.exists()
    assert result.new_path == db

    async with CredentialStore(_config(db, new_key)) as store:
        after = await store.query(limit=100)
    assert len(after) == 5
    seen = {(r.source_ip, r.username, r.password) for r in after}
    expected = {(r.source_ip, r.username, r.password) for r in before}
    assert seen == expected


async def test_old_key_no_longer_decrypts(tmp_path: Path) -> None:
    db = tmp_path / "creds.db"
    old_key = _key(7)
    new_key = _key(8)
    async with CredentialStore(_config(db, old_key)) as store:
        await _populate(store, count=3)
    rotate_key(
        db_path=db,
        old_cipher=CredentialCipher(old_key),
        new_cipher=CredentialCipher(new_key),
    )
    # Opening with the OLD key should now silently skip everything.
    async with CredentialStore(_config(db, old_key)) as store:
        records = await store.query(limit=100)
    assert records == []


async def test_missing_db_raises(tmp_path: Path) -> None:
    with pytest.raises(RotationError, match="not found"):
        rotate_key(
            db_path=tmp_path / "absent.db",
            old_cipher=CredentialCipher(_key(1)),
            new_cipher=CredentialCipher(_key(2)),
        )


async def test_pre_existing_workfile_blocks_rotation(tmp_path: Path) -> None:
    db = tmp_path / "creds.db"
    async with CredentialStore(_config(db, _key(1))) as store:
        await _populate(store, count=1)
    (tmp_path / "creds.db.new").write_text("leftover", encoding="utf-8")
    with pytest.raises(RotationError, match="work file"):
        rotate_key(
            db_path=db,
            old_cipher=CredentialCipher(_key(1)),
            new_cipher=CredentialCipher(_key(2)),
        )


async def test_pre_existing_backup_blocks_rotation(tmp_path: Path) -> None:
    db = tmp_path / "creds.db"
    async with CredentialStore(_config(db, _key(1))) as store:
        await _populate(store, count=1)
    (tmp_path / "creds.db.bak").write_text("leftover", encoding="utf-8")
    with pytest.raises(RotationError, match="backup"):
        rotate_key(
            db_path=db,
            old_cipher=CredentialCipher(_key(1)),
            new_cipher=CredentialCipher(_key(2)),
        )


async def test_rotation_skips_undecryptable_rows(tmp_path: Path) -> None:
    """A row with mismatched-cipher ciphertext is counted, not aborted on."""
    db = tmp_path / "creds.db"
    async with CredentialStore(_config(db, _key(1))) as store:
        await _populate(store, count=3)

    # Inject a row encrypted with a *different* key into the same DB.
    foreign_cipher = CredentialCipher(_key(99))
    foreign_ct, foreign_nonce = foreign_cipher.encrypt("alien")
    conn = sqlite3.connect(str(db))
    try:
        conn.execute(
            "INSERT INTO attempts ("
            "source_ip, session_id, username_ct, username_nonce, "
            "password_ct, password_nonce, username_fp, password_fp, "
            "first_seen, last_seen, attempt_count"
            ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                "1.2.3.4",
                str(uuid4()),
                foreign_ct,
                foreign_nonce,
                foreign_ct,
                foreign_nonce,
                foreign_cipher.fingerprint("alien"),
                foreign_cipher.fingerprint("alien"),
                "2026-05-22T00:00:00+00:00",
                "2026-05-22T00:00:00+00:00",
                1,
            ),
        )
        conn.commit()
    finally:
        conn.close()

    result = rotate_key(
        db_path=db,
        old_cipher=CredentialCipher(_key(1)),
        new_cipher=CredentialCipher(_key(2)),
    )
    assert result.rows_rotated == 3
    assert result.rows_skipped == 1
