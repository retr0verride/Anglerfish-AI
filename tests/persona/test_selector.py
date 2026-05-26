"""Tests for the Stage 9 slice 9.2 :class:`PersonaSelector`."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import pytest

from anglerfish.config.models import SessionStoreConfig
from anglerfish.models.session import SessionSnapshot
from anglerfish.persona import (
    DEFAULT_PERSONA_NAME,
    PersonaRegistry,
    PersonaSelector,
)
from anglerfish.persona.schema import Persona
from anglerfish.sessions import SessionStore
from anglerfish.sessions.reader import SessionStoreReader


def _persona(name: str) -> Persona:
    return Persona(
        name=name,
        description=f"Persona named {name}.",
        hostname=name,
        username="root",
        cwd="/root",
        prompt_block=f"The {name} persona.",
    )


def _registry() -> PersonaRegistry:
    return PersonaRegistry(
        {
            DEFAULT_PERSONA_NAME: _persona(DEFAULT_PERSONA_NAME),
            "gpu-rig": _persona("gpu-rig"),
            "dev-laptop": _persona("dev-laptop"),
        },
    )


async def _opened_reader(tmp_path: Path) -> tuple[SessionStoreReader, SessionStore]:
    """Open a writer (to migrate the DB) then a read-only reader handle."""
    config = SessionStoreConfig(database_path=tmp_path / "sessions.db")
    store = SessionStore(config)
    await store.open()
    reader = SessionStoreReader(config)
    await reader.open()
    return reader, store


async def _seed_session_with_persona(
    store: SessionStore,
    *,
    source_ip: str,
    persona_name: str,
    started_at: datetime,
) -> None:
    snap = SessionSnapshot(
        session_id=uuid4(),
        source_ip=source_ip,
        username="root",
        fake_hostname=persona_name,
        fake_username="root",
        fake_cwd="/root",
        started_at=started_at,
        last_activity_at=started_at,
        turns=(),
        persona_name=persona_name,
    )
    await store.upsert_session(snap)


async def _set_pin(store: SessionStore, source_ip: str, persona: str) -> None:
    """Insert a row directly into persona_pins for selector lookups."""
    now = datetime(2026, 5, 26, 12, 0, tzinfo=UTC).isoformat()
    async with store._lock:  # type: ignore[attr-defined]
        store._conn.execute(  # type: ignore[union-attr]
            "INSERT INTO persona_pins (source_ip, persona, created_at, created_by) "
            "VALUES (?, ?, ?, ?)",
            (source_ip, persona, now, "test"),
        )


# ---------------------------------------------------------------------------
# Selection order
# ---------------------------------------------------------------------------


async def test_select_pin_wins_over_recurrence(tmp_path: Path) -> None:
    reader, store = await _opened_reader(tmp_path)
    try:
        ip = "203.0.113.7"
        await _seed_session_with_persona(
            store,
            source_ip=ip,
            persona_name="dev-laptop",
            started_at=datetime(2026, 5, 25, tzinfo=UTC),
        )
        await _set_pin(store, ip, "gpu-rig")
        selector = PersonaSelector(_registry(), reader)
        result = await selector.select(ip)
        assert result.persona.name == "gpu-rig"
        assert result.reason == "pin"
    finally:
        await reader.aclose()
        await store.aclose()


async def test_select_recurrence_wins_over_hash(tmp_path: Path) -> None:
    reader, store = await _opened_reader(tmp_path)
    try:
        ip = "203.0.113.8"
        await _seed_session_with_persona(
            store,
            source_ip=ip,
            persona_name="dev-laptop",
            started_at=datetime(2026, 5, 25, tzinfo=UTC),
        )
        selector = PersonaSelector(_registry(), reader)
        result = await selector.select(ip)
        assert result.persona.name == "dev-laptop"
        assert result.reason == "source_ip_recurrence"
    finally:
        await reader.aclose()
        await store.aclose()


async def test_select_recurrence_picks_most_recent(tmp_path: Path) -> None:
    """Two prior sessions, different personas; newest wins."""
    reader, store = await _opened_reader(tmp_path)
    try:
        ip = "203.0.113.9"
        await _seed_session_with_persona(
            store,
            source_ip=ip,
            persona_name="gpu-rig",
            started_at=datetime(2026, 5, 24, tzinfo=UTC),
        )
        await _seed_session_with_persona(
            store,
            source_ip=ip,
            persona_name="dev-laptop",
            started_at=datetime(2026, 5, 26, tzinfo=UTC),
        )
        selector = PersonaSelector(_registry(), reader)
        result = await selector.select(ip)
        assert result.persona.name == "dev-laptop"
        assert result.reason == "source_ip_recurrence"
    finally:
        await reader.aclose()
        await store.aclose()


async def test_select_hash_fallback_when_no_signal(tmp_path: Path) -> None:
    reader, store = await _opened_reader(tmp_path)
    try:
        selector = PersonaSelector(_registry(), reader)
        result = await selector.select("198.51.100.55")
        assert result.reason == "hash_fallback"
        assert result.persona.name in _registry().names()
    finally:
        await reader.aclose()
        await store.aclose()


async def test_select_hash_fallback_is_deterministic(tmp_path: Path) -> None:
    """Same source IP -> same fallback persona every call."""
    reader, store = await _opened_reader(tmp_path)
    try:
        selector = PersonaSelector(_registry(), reader)
        first = await selector.select("198.51.100.1")
        second = await selector.select("198.51.100.1")
        assert first.persona.name == second.persona.name
    finally:
        await reader.aclose()
        await store.aclose()


async def test_select_hash_fallback_distributes_across_personas(tmp_path: Path) -> None:
    """Across many IPs, every persona should see at least one hit."""
    reader, store = await _opened_reader(tmp_path)
    try:
        selector = PersonaSelector(_registry(), reader)
        hits: set[str] = set()
        for i in range(200):
            result = await selector.select(f"10.0.0.{i}")
            hits.add(result.persona.name)
        assert hits == set(_registry().names())
    finally:
        await reader.aclose()
        await store.aclose()


async def test_select_recurrence_ignores_unknown_persona_names(
    tmp_path: Path,
) -> None:
    """A session row referencing a persona the operator deleted falls back."""
    reader, store = await _opened_reader(tmp_path)
    try:
        ip = "203.0.113.10"
        await _seed_session_with_persona(
            store,
            source_ip=ip,
            persona_name="deleted-by-operator",
            started_at=datetime(2026, 5, 25, tzinfo=UTC),
        )
        selector = PersonaSelector(_registry(), reader)
        result = await selector.select(ip)
        assert result.reason == "hash_fallback"
    finally:
        await reader.aclose()
        await store.aclose()


async def test_select_pin_ignores_unknown_persona_names(tmp_path: Path) -> None:
    """A pin referencing a now-deleted persona falls through."""
    reader, store = await _opened_reader(tmp_path)
    try:
        ip = "203.0.113.11"
        await _set_pin(store, ip, "deleted-persona")
        selector = PersonaSelector(_registry(), reader)
        result = await selector.select(ip)
        assert result.reason == "hash_fallback"
    finally:
        await reader.aclose()
        await store.aclose()


async def test_select_empty_source_ip_raises(tmp_path: Path) -> None:
    reader, store = await _opened_reader(tmp_path)
    try:
        selector = PersonaSelector(_registry(), reader)
        with pytest.raises(ValueError, match="source_ip cannot be empty"):
            await selector.select("")
    finally:
        await reader.aclose()
        await store.aclose()


async def test_select_only_considers_non_null_persona_rows(
    tmp_path: Path,
) -> None:
    """Pre-Stage-9 sessions (persona IS NULL) do not count as recurrence."""
    reader, store = await _opened_reader(tmp_path)
    try:
        ip = "203.0.113.12"
        # Insert a pre-Stage-9-style row with NULL persona.
        snap = SessionSnapshot(
            session_id=uuid4(),
            source_ip=ip,
            username="root",
            fake_hostname="legacy-host",
            fake_username="root",
            fake_cwd="/root",
            started_at=datetime(2026, 4, 1, tzinfo=UTC),
            last_activity_at=datetime(2026, 4, 1, tzinfo=UTC),
            turns=(),
            persona_name=None,
        )
        await store.upsert_session(snap)
        selector = PersonaSelector(_registry(), reader)
        result = await selector.select(ip)
        assert result.reason == "hash_fallback"
    finally:
        await reader.aclose()
        await store.aclose()
