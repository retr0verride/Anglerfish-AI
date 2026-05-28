"""Tests for the Stage 9 :class:`SessionStoreReader` read-only facade."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import pytest

from anglerfish.config.models import SessionStoreConfig
from anglerfish.models.session import SessionSnapshot
from anglerfish.sessions import SessionStore
from anglerfish.sessions.reader import SessionStoreReader


async def _make_writer(tmp_path: Path) -> tuple[SessionStore, SessionStoreConfig]:
    config = SessionStoreConfig(database_path=tmp_path / "sessions.db")
    store = SessionStore(config)
    await store.open()
    return store, config


def _snapshot(
    *,
    source_ip: str = "203.0.113.7",
    persona_name: str | None = None,
    started_at: datetime | None = None,
) -> SessionSnapshot:
    now = started_at or datetime(2026, 5, 26, 12, 0, tzinfo=UTC)
    return SessionSnapshot(
        session_id=uuid4(),
        source_ip=source_ip,
        username="root",
        fake_hostname="srv-prod-01",
        fake_username="root",
        fake_cwd="/root",
        started_at=now,
        last_activity_at=now,
        turns=(),
        persona_name=persona_name,
    )


# ---------------------------------------------------------------------------
# Lifecycle
# ---------------------------------------------------------------------------


async def test_open_raises_if_db_missing(tmp_path: Path) -> None:
    config = SessionStoreConfig(database_path=tmp_path / "missing.db")
    reader = SessionStoreReader(config)
    with pytest.raises(FileNotFoundError, match="database file not found"):
        await reader.open()


async def test_open_is_idempotent(tmp_path: Path) -> None:
    writer, config = await _make_writer(tmp_path)
    try:
        reader = SessionStoreReader(config)
        await reader.open()
        await reader.open()  # second call: no-op
        assert reader.is_open
        await reader.aclose()
    finally:
        await writer.aclose()


async def test_query_before_open_raises(tmp_path: Path) -> None:
    writer, config = await _make_writer(tmp_path)
    try:
        reader = SessionStoreReader(config)
        with pytest.raises(RuntimeError, match="open\\(\\) must be awaited"):
            await reader.recent_persona_for_source_ip("1.2.3.4")
    finally:
        await writer.aclose()


# ---------------------------------------------------------------------------
# recent_persona_for_source_ip
# ---------------------------------------------------------------------------


async def test_recent_persona_returns_none_when_no_rows(tmp_path: Path) -> None:
    writer, config = await _make_writer(tmp_path)
    try:
        async with SessionStoreReader(config) as reader:
            assert await reader.recent_persona_for_source_ip("1.1.1.1") is None
    finally:
        await writer.aclose()


async def test_recent_persona_returns_most_recent_match(tmp_path: Path) -> None:
    writer, config = await _make_writer(tmp_path)
    try:
        await writer.upsert_session(
            _snapshot(
                source_ip="203.0.113.7",
                persona_name="gpu-rig",
                started_at=datetime(2026, 5, 24, tzinfo=UTC),
            ),
        )
        await writer.upsert_session(
            _snapshot(
                source_ip="203.0.113.7",
                persona_name="dev-laptop",
                started_at=datetime(2026, 5, 26, tzinfo=UTC),
            ),
        )
        async with SessionStoreReader(config) as reader:
            persona = await reader.recent_persona_for_source_ip("203.0.113.7")
        assert persona == "dev-laptop"
    finally:
        await writer.aclose()


async def test_recent_persona_filters_null_persona_rows(tmp_path: Path) -> None:
    writer, config = await _make_writer(tmp_path)
    try:
        # A pre-Stage-9-style row: persona IS NULL but is newer than
        # the Stage 9 row. The selector must not return None just
        # because the latest row has no persona; it must reach back
        # to the most recent NON-NULL persona.
        await writer.upsert_session(
            _snapshot(
                source_ip="203.0.113.7",
                persona_name="gpu-rig",
                started_at=datetime(2026, 5, 24, tzinfo=UTC),
            ),
        )
        await writer.upsert_session(
            _snapshot(
                source_ip="203.0.113.7",
                persona_name=None,
                started_at=datetime(2026, 5, 26, tzinfo=UTC),
            ),
        )
        async with SessionStoreReader(config) as reader:
            persona = await reader.recent_persona_for_source_ip("203.0.113.7")
        assert persona == "gpu-rig"
    finally:
        await writer.aclose()


# ---------------------------------------------------------------------------
# get_persona_pin
# ---------------------------------------------------------------------------


async def test_get_persona_pin_returns_none_when_no_row(tmp_path: Path) -> None:
    writer, config = await _make_writer(tmp_path)
    try:
        async with SessionStoreReader(config) as reader:
            assert await reader.get_persona_pin("1.2.3.4") is None
    finally:
        await writer.aclose()


async def test_get_persona_pin_returns_persona_when_pinned(tmp_path: Path) -> None:
    writer, config = await _make_writer(tmp_path)
    try:
        # Insert directly; the dashboard's POST /api/persona/pin
        # endpoint ships in slice 9.4.
        async with writer._lock:
            writer._conn.execute(  # type: ignore[union-attr]
                "INSERT INTO persona_pins (source_ip, persona, created_at, created_by) "
                "VALUES (?, ?, ?, ?)",
                ("203.0.113.7", "gpu-rig", "2026-05-26T12:00:00+00:00", "operator"),
            )
        async with SessionStoreReader(config) as reader:
            assert await reader.get_persona_pin("203.0.113.7") == "gpu-rig"
    finally:
        await writer.aclose()


async def test_reader_persists_persona_on_session_snapshot(tmp_path: Path) -> None:
    """Round-trip the persona column through upsert + get."""
    writer, _config = await _make_writer(tmp_path)
    try:
        snap = _snapshot(persona_name="ad-joined-workstation")
        await writer.upsert_session(snap)
        loaded = await writer.get_session(snap.session_id)
        assert loaded is not None
        assert loaded.persona_name == "ad-joined-workstation"
    finally:
        await writer.aclose()


# ---------------------------------------------------------------------------
# Stage 9 slice 9.4: SessionStore persona_pins CRUD + update_session_persona
# ---------------------------------------------------------------------------


async def test_persona_pin_round_trip(tmp_path: Path) -> None:
    writer, config = await _make_writer(tmp_path)
    try:
        await writer.upsert_persona_pin(
            source_ip="203.0.113.7",
            persona="gpu-rig",
            created_by="operator",
        )
        async with SessionStoreReader(config) as reader:
            assert await reader.get_persona_pin("203.0.113.7") == "gpu-rig"
    finally:
        await writer.aclose()


async def test_persona_pin_upsert_overwrites(tmp_path: Path) -> None:
    writer, config = await _make_writer(tmp_path)
    try:
        await writer.upsert_persona_pin(
            source_ip="203.0.113.7",
            persona="gpu-rig",
            created_by="op1",
        )
        latest = await writer.upsert_persona_pin(
            source_ip="203.0.113.7",
            persona="dev-laptop",
            created_by="op2",
        )
        assert latest.persona == "dev-laptop"
        assert latest.created_by == "op2"
        async with SessionStoreReader(config) as reader:
            assert await reader.get_persona_pin("203.0.113.7") == "dev-laptop"
    finally:
        await writer.aclose()


async def test_list_persona_pins_newest_first(tmp_path: Path) -> None:
    writer, _ = await _make_writer(tmp_path)
    try:
        # Two distinct IPs so neither upserts over the other; the
        # second insert produces a later created_at.
        await writer.upsert_persona_pin(
            source_ip="203.0.113.1",
            persona="gpu-rig",
            created_by="op",
        )
        # Tiny delay so created_at strictly orders.
        import asyncio

        await asyncio.sleep(0.01)
        await writer.upsert_persona_pin(
            source_ip="203.0.113.2",
            persona="dev-laptop",
            created_by="op",
        )
        pins = await writer.list_persona_pins()
        assert [p.source_ip for p in pins] == ["203.0.113.2", "203.0.113.1"]
    finally:
        await writer.aclose()


async def test_delete_persona_pin_returns_true_when_removed(tmp_path: Path) -> None:
    writer, _ = await _make_writer(tmp_path)
    try:
        await writer.upsert_persona_pin(
            source_ip="203.0.113.7",
            persona="gpu-rig",
            created_by="op",
        )
        assert await writer.delete_persona_pin("203.0.113.7") is True
        assert await writer.delete_persona_pin("203.0.113.7") is False
    finally:
        await writer.aclose()


async def test_update_session_persona_rewrites_value(tmp_path: Path) -> None:
    writer, _ = await _make_writer(tmp_path)
    try:
        snap = _snapshot(persona_name="forgotten-debian-box")
        await writer.upsert_session(snap)
        changed = await writer.update_session_persona(snap.session_id, "gpu-rig")
        assert changed is True
        reloaded = await writer.get_session(snap.session_id)
        assert reloaded is not None
        assert reloaded.persona_name == "gpu-rig"
    finally:
        await writer.aclose()


async def test_update_session_persona_unknown_session_returns_false(
    tmp_path: Path,
) -> None:
    writer, _ = await _make_writer(tmp_path)
    try:
        from uuid import uuid4

        changed = await writer.update_session_persona(uuid4(), "gpu-rig")
        assert changed is False
    finally:
        await writer.aclose()
