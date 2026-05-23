"""Tests for ``anglerfish credentials rotate-key``."""

from __future__ import annotations

import base64
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import pytest
from pydantic import SecretStr
from typer.testing import CliRunner

from anglerfish.audit import AuditLog
from anglerfish.cli.__main__ import app
from anglerfish.config.models import CredentialsConfig
from anglerfish.credentials import CredentialStore


def _key(byte: int) -> str:
    return base64.b64encode(bytes([byte] * 32)).decode("ascii")


def _config(path: Path, key: str) -> CredentialsConfig:
    return CredentialsConfig(database_path=path, encryption_key=SecretStr(key))


async def _populate(store: CredentialStore) -> None:
    await store.record_attempt(
        source_ip="203.0.113.7",
        username="root",
        password="hunter2",
        session_id=uuid4(),
        timestamp=datetime(2026, 5, 22, tzinfo=UTC),
    )


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


def _stage_creds_env(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    old_key: str,
) -> Path:
    """Wire load_settings() to point at a tmp credentials DB."""
    db = tmp_path / "creds.db"

    monkeypatch.setenv(
        "ANGLERFISH_DASHBOARD__SESSION_SECRET",
        "x" * 40,
    )
    monkeypatch.setenv("ANGLERFISH_CREDENTIALS__ENCRYPTION_KEY", old_key)
    monkeypatch.setenv("ANGLERFISH_CREDENTIALS__DATABASE_PATH", str(db))
    # AuditLog defaults to /var/log/anglerfish; redirect for the test.
    audit_path = tmp_path / "audit.jsonl"

    def _audit_factory(*_args: object, **_kwargs: object) -> AuditLog:
        return AuditLog(audit_path)

    monkeypatch.setattr("anglerfish.cli.__main__.AuditLog", _audit_factory)
    return db


async def test_rotate_key_happy_path(
    runner: CliRunner,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    old_key = _key(1)
    new_key = _key(2)
    db = _stage_creds_env(monkeypatch, tmp_path, old_key=old_key)

    async with CredentialStore(_config(db, old_key)) as store:
        await _populate(store)

    result = runner.invoke(
        app,
        ["credentials", "rotate-key", "--new-key", new_key, "--yes"],
    )
    assert result.exit_code == 0, result.output
    assert "Rotated 1 records" in result.output
    assert db.exists()
    backup = db.with_suffix(db.suffix + ".bak")
    assert backup.exists()

    # New DB should be decryptable with the new key.
    async with CredentialStore(_config(db, new_key)) as store:
        rows = await store.query(limit=10)
    assert len(rows) == 1
    assert rows[0].username == "root"


def test_rotate_key_missing_db_exits_1(
    runner: CliRunner,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    old_key = _key(1)
    new_key = _key(2)
    _stage_creds_env(monkeypatch, tmp_path, old_key=old_key)
    # Database not created.

    result = runner.invoke(
        app,
        ["credentials", "rotate-key", "--new-key", new_key, "--yes"],
    )
    assert result.exit_code == 1
    assert "No credentials database" in result.output


def test_rotate_key_invalid_new_key_exits_1(
    runner: CliRunner,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    old_key = _key(1)
    db = _stage_creds_env(monkeypatch, tmp_path, old_key=old_key)
    db.touch()  # Make path exist; the rotation will fail on the key

    result = runner.invoke(
        app,
        ["credentials", "rotate-key", "--new-key", "not!base64!", "--yes"],
    )
    assert result.exit_code == 1
    assert "Invalid encryption key" in result.output


async def test_rotate_key_aborted_by_operator(
    runner: CliRunner,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    old_key = _key(1)
    new_key = _key(2)
    db = _stage_creds_env(monkeypatch, tmp_path, old_key=old_key)
    async with CredentialStore(_config(db, old_key)) as store:
        await _populate(store)

    # Without --yes, the prompt defaults to No.
    result = runner.invoke(
        app,
        ["credentials", "rotate-key", "--new-key", new_key],
        input="n\n",
    )
    assert result.exit_code == 1
    assert "Aborted" in result.output
