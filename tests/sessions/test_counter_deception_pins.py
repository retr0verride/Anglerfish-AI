"""Stage 12 slice 12.4: counter_deception_pins store + reader (schema v7)."""

from __future__ import annotations

from pathlib import Path

from anglerfish.config.models import CounterDeceptionMode, SessionStoreConfig
from anglerfish.sessions.reader import SessionStoreReader
from anglerfish.sessions.schema import CURRENT_SCHEMA_VERSION
from anglerfish.sessions.store import SessionStore


def _cfg(tmp_path: Path) -> SessionStoreConfig:
    return SessionStoreConfig(database_path=tmp_path / "sessions.db")


async def test_schema_is_v7(tmp_path: Path) -> None:
    assert CURRENT_SCHEMA_VERSION == 7
    store = SessionStore(_cfg(tmp_path))
    await store.open()
    try:
        # The table exists after migration; a list query succeeds.
        assert await store.list_counter_deception_pins() == []
    finally:
        await store.aclose()


async def test_upsert_and_list(tmp_path: Path) -> None:
    store = SessionStore(_cfg(tmp_path))
    await store.open()
    try:
        pin = await store.upsert_counter_deception_pin(
            source_ip="203.0.113.7",
            mode=CounterDeceptionMode.BOTH,
            created_by="operator",
        )
        assert pin.source_ip == "203.0.113.7"
        assert pin.mode is CounterDeceptionMode.BOTH
        assert pin.created_by == "operator"
        pins = await store.list_counter_deception_pins()
        assert len(pins) == 1
        assert pins[0].mode is CounterDeceptionMode.BOTH
    finally:
        await store.aclose()


async def test_repin_overwrites_same_ip(tmp_path: Path) -> None:
    store = SessionStore(_cfg(tmp_path))
    await store.open()
    try:
        await store.upsert_counter_deception_pin(
            source_ip="203.0.113.7",
            mode=CounterDeceptionMode.GARBLE,
            created_by="op1",
        )
        await store.upsert_counter_deception_pin(
            source_ip="203.0.113.7",
            mode=CounterDeceptionMode.OFF,
            created_by="op2",
        )
        pins = await store.list_counter_deception_pins()
        assert len(pins) == 1
        assert pins[0].mode is CounterDeceptionMode.OFF
        assert pins[0].created_by == "op2"
    finally:
        await store.aclose()


async def test_delete(tmp_path: Path) -> None:
    store = SessionStore(_cfg(tmp_path))
    await store.open()
    try:
        await store.upsert_counter_deception_pin(
            source_ip="203.0.113.7",
            mode=CounterDeceptionMode.TIMEBOMB,
            created_by="op",
        )
        assert await store.delete_counter_deception_pin("203.0.113.7") is True
        assert await store.list_counter_deception_pins() == []
        # Deleting a missing pin returns False.
        assert await store.delete_counter_deception_pin("203.0.113.7") is False
    finally:
        await store.aclose()


async def test_reader_get_returns_mode_string(tmp_path: Path) -> None:
    cfg = _cfg(tmp_path)
    writer = SessionStore(cfg)
    await writer.open()
    await writer.upsert_counter_deception_pin(
        source_ip="203.0.113.7",
        mode=CounterDeceptionMode.GARBLE,
        created_by="op",
    )
    await writer.aclose()

    reader = SessionStoreReader(cfg)
    await reader.open()
    try:
        assert await reader.get_counter_deception_pin("203.0.113.7") == "garble"
        assert await reader.get_counter_deception_pin("8.8.8.8") is None
    finally:
        await reader.aclose()
