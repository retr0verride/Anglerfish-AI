"""Tests for :class:`anglerfish.credentials.CredentialStore`."""

from __future__ import annotations

import base64
import sys
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import pytest
from pydantic import SecretStr

from anglerfish.config.models import CredentialsConfig
from anglerfish.credentials import CredentialStore


def _config(path: Path) -> CredentialsConfig:
    return CredentialsConfig(
        database_path=path,
        encryption_key=SecretStr(base64.b64encode(b"\x07" * 32).decode("ascii")),
    )


async def test_open_creates_database(tmp_path: Path) -> None:
    db = tmp_path / "creds.db"
    store = CredentialStore(_config(db))
    await store.open()
    try:
        assert db.exists()
        assert store.is_open is True
    finally:
        await store.aclose()


async def test_record_attempt_inserts_new_then_increments(tmp_path: Path) -> None:
    db = tmp_path / "creds.db"
    sid = uuid4()
    ts = datetime(2026, 5, 22, tzinfo=UTC)
    async with CredentialStore(_config(db)) as store:
        is_new_1 = await store.record_attempt(
            source_ip="203.0.113.7",
            username="root",
            password="hunter2",
            session_id=sid,
            timestamp=ts,
        )
        is_new_2 = await store.record_attempt(
            source_ip="203.0.113.7",
            username="root",
            password="hunter2",
            session_id=sid,
            timestamp=ts,
        )
        records = await store.query()
    assert is_new_1 is True
    assert is_new_2 is False
    assert len(records) == 1
    assert records[0].attempt_count == 2
    assert records[0].username == "root"
    assert records[0].password == "hunter2"


async def test_record_attempt_dedupes_per_source_ip(tmp_path: Path) -> None:
    db = tmp_path / "creds.db"
    sid = uuid4()
    ts = datetime(2026, 5, 22, tzinfo=UTC)
    async with CredentialStore(_config(db)) as store:
        await store.record_attempt(
            source_ip="203.0.113.7",
            username="root",
            password="hunter2",
            session_id=sid,
            timestamp=ts,
        )
        await store.record_attempt(
            source_ip="203.0.113.8",  # different IP — counted as new
            username="root",
            password="hunter2",
            session_id=sid,
            timestamp=ts,
        )
        records = await store.query()
    assert len(records) == 2


async def test_record_attempt_enforces_per_source_ip_cap(tmp_path: Path) -> None:
    """Once a source IP hits the unique-credentials cap, new pairs are dropped."""
    db = tmp_path / "creds.db"
    sid = uuid4()
    ts = datetime(2026, 5, 22, tzinfo=UTC)
    config = CredentialsConfig(
        database_path=db,
        encryption_key=SecretStr(base64.b64encode(b"\x07" * 32).decode("ascii")),
        max_unique_per_source_ip=3,
    )
    async with CredentialStore(config) as store:
        # 3 distinct pairs from the same IP — all accepted.
        for i in range(3):
            assert (
                await store.record_attempt(
                    source_ip="203.0.113.7",
                    username=f"u{i}",
                    password=f"p{i}",
                    session_id=sid,
                    timestamp=ts,
                )
                is True
            )
        # 4th unique pair from same IP — dropped (returns False).
        assert (
            await store.record_attempt(
                source_ip="203.0.113.7",
                username="overflow",
                password="x",
                session_id=sid,
                timestamp=ts,
            )
            is False
        )
        # Existing pair on the same IP still increments — the cap is on
        # *unique* inserts, not on attempt counting.
        assert (
            await store.record_attempt(
                source_ip="203.0.113.7",
                username="u0",
                password="p0",
                session_id=sid,
                timestamp=ts,
            )
            is False
        )
        # Different source IP still gets its own quota.
        assert (
            await store.record_attempt(
                source_ip="203.0.113.8",
                username="root",
                password="hunter2",
                session_id=sid,
                timestamp=ts,
            )
            is True
        )
        records = await store.query()
    assert len(records) == 4  # 3 from .7 + 1 from .8
    by_ip = {r.source_ip: r for r in records if r.source_ip == "203.0.113.7"}
    assert by_ip["203.0.113.7"].attempt_count == 2  # u0/p0 was hit twice


async def test_record_attempt_cap_zero_disables_limit(tmp_path: Path) -> None:
    db = tmp_path / "creds.db"
    sid = uuid4()
    ts = datetime(2026, 5, 22, tzinfo=UTC)
    config = CredentialsConfig(
        database_path=db,
        encryption_key=SecretStr(base64.b64encode(b"\x07" * 32).decode("ascii")),
        max_unique_per_source_ip=0,
    )
    async with CredentialStore(config) as store:
        for i in range(50):
            assert (
                await store.record_attempt(
                    source_ip="203.0.113.7",
                    username=f"u{i}",
                    password="p",
                    session_id=sid,
                    timestamp=ts,
                )
                is True
            )
        records = await store.query(limit=1000)
    assert len(records) == 50


async def test_query_filters_by_source_ip(tmp_path: Path) -> None:
    db = tmp_path / "creds.db"
    sid = uuid4()
    ts = datetime(2026, 5, 22, tzinfo=UTC)
    async with CredentialStore(_config(db)) as store:
        await store.record_attempt(
            source_ip="1.1.1.1",
            username="a",
            password="b",
            session_id=sid,
            timestamp=ts,
        )
        await store.record_attempt(
            source_ip="2.2.2.2",
            username="c",
            password="d",
            session_id=sid,
            timestamp=ts,
        )
        filtered = await store.query(source_ip="2.2.2.2")
    assert len(filtered) == 1
    assert filtered[0].source_ip == "2.2.2.2"


async def test_query_pagination(tmp_path: Path) -> None:
    db = tmp_path / "creds.db"
    sid = uuid4()
    base_ts = datetime(2026, 5, 22, tzinfo=UTC)
    async with CredentialStore(_config(db)) as store:
        for i in range(5):
            await store.record_attempt(
                source_ip=f"1.1.1.{i}",
                username=f"u{i}",
                password="p",
                session_id=sid,
                timestamp=base_ts.replace(microsecond=i),
            )
        page = await store.query(limit=2, offset=1)
    assert len(page) == 2


async def test_query_validates_bounds(tmp_path: Path) -> None:
    db = tmp_path / "creds.db"
    async with CredentialStore(_config(db)) as store:
        with pytest.raises(ValueError):
            await store.query(limit=0)
        with pytest.raises(ValueError):
            await store.query(offset=-1)


async def test_stats(tmp_path: Path) -> None:
    db = tmp_path / "creds.db"
    sid = uuid4()
    ts = datetime(2026, 5, 22, tzinfo=UTC)
    async with CredentialStore(_config(db)) as store:
        await store.record_attempt(
            source_ip="1.1.1.1",
            username="a",
            password="x",
            session_id=sid,
            timestamp=ts,
        )
        await store.record_attempt(
            source_ip="1.1.1.1",
            username="a",
            password="x",
            session_id=sid,
            timestamp=ts,
        )  # same combo → +1 count, no new combo
        await store.record_attempt(
            source_ip="1.1.1.1",
            username="a",
            password="y",
            session_id=sid,
            timestamp=ts,
        )
        await store.record_attempt(
            source_ip="2.2.2.2",
            username="b",
            password="x",
            session_id=sid,
            timestamp=ts,
        )
        stats = await store.stats()
    assert stats.total_attempts == 4
    assert stats.unique_combinations == 3
    assert stats.unique_usernames == 2
    assert stats.unique_passwords == 2
    assert stats.unique_source_ips == 2


async def test_stats_empty_db(tmp_path: Path) -> None:
    db = tmp_path / "creds.db"
    async with CredentialStore(_config(db)) as store:
        stats = await store.stats()
    assert stats.total_attempts == 0
    assert stats.unique_combinations == 0


async def test_methods_require_open(tmp_path: Path) -> None:
    db = tmp_path / "creds.db"
    store = CredentialStore(_config(db))
    with pytest.raises(RuntimeError):
        await store.record_attempt(
            source_ip="x",
            username="y",
            password="z",
            session_id=uuid4(),
            timestamp=datetime.now(UTC),
        )
    with pytest.raises(RuntimeError):
        await store.query()
    with pytest.raises(RuntimeError):
        await store.stats()


async def test_open_is_idempotent(tmp_path: Path) -> None:
    db = tmp_path / "creds.db"
    store = CredentialStore(_config(db))
    await store.open()
    await store.open()
    await store.aclose()


async def test_aclose_is_idempotent(tmp_path: Path) -> None:
    db = tmp_path / "creds.db"
    store = CredentialStore(_config(db))
    await store.aclose()  # not yet opened
    await store.open()
    await store.aclose()
    await store.aclose()


async def test_persisted_data_survives_reopen(tmp_path: Path) -> None:
    db = tmp_path / "creds.db"
    sid = uuid4()
    ts = datetime(2026, 5, 22, tzinfo=UTC)
    async with CredentialStore(_config(db)) as store:
        await store.record_attempt(
            source_ip="1.1.1.1",
            username="alice",
            password="bob",
            session_id=sid,
            timestamp=ts,
        )
    async with CredentialStore(_config(db)) as store:
        records = await store.query()
    assert len(records) == 1
    assert records[0].username == "alice"
    assert records[0].password == "bob"


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permission semantics")
async def test_database_file_mode_is_0600(tmp_path: Path) -> None:
    db = tmp_path / "creds.db"
    async with CredentialStore(_config(db)):
        pass
    mode = db.stat().st_mode & 0o777
    assert mode == 0o600


async def test_records_decrypt_with_correct_key(tmp_path: Path) -> None:
    db = tmp_path / "creds.db"
    cfg = _config(db)
    sid = uuid4()
    ts = datetime(2026, 5, 22, tzinfo=UTC)
    async with CredentialStore(cfg) as store:
        await store.record_attempt(
            source_ip="1.1.1.1",
            username="admin",
            password="P@ssw0rd!",
            session_id=sid,
            timestamp=ts,
        )
        rows = await store.query()
    assert rows[0].password == "P@ssw0rd!"


async def test_records_with_mismatched_key_are_skipped(tmp_path: Path) -> None:
    """A key swap simulates a key rotation accident — old rows must not crash."""
    db = tmp_path / "creds.db"
    sid = uuid4()
    ts = datetime(2026, 5, 22, tzinfo=UTC)
    async with CredentialStore(_config(db)) as store:
        await store.record_attempt(
            source_ip="1.1.1.1",
            username="x",
            password="y",
            session_id=sid,
            timestamp=ts,
        )
    # Build a *different* config (different key) pointing at the same DB.
    other_key = base64.b64encode(b"\x09" * 32).decode("ascii")
    other = CredentialsConfig(
        database_path=db,
        encryption_key=SecretStr(other_key),
    )
    async with CredentialStore(other) as store:
        rows = await store.query()
    assert rows == []  # silently skipped, no crash
