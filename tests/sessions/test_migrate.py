"""Tests for :func:`anglerfish.sessions.import_jsonl_into_store`.

The helper is the one-shot operator path for replaying the
forwarder's JSONL fallback into the Stage 4 session store; the
docs/RUNBOOK.md "Import old forwarder JSONL" section documents the
one-liner that drives it.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from anglerfish.sessions import import_jsonl_into_store
from anglerfish.sessions.store import SessionStore


def _envelope(event: dict[str, object]) -> str:
    """Forwarder envelope: {"event": <cowrie-event>}, one line of JSONL."""
    return json.dumps({"event": event}, separators=(",", ":")) + "\n"


def _connect_event(
    cowrie_sid: str,
    *,
    src_ip: str = "203.0.113.7",
    ts: str = "2026-05-22T10:00:00+00:00",
) -> dict[str, object]:
    return {
        "session": cowrie_sid,
        "eventid": "cowrie.session.connect",
        "src_ip": src_ip,
        "username": "root",
        "timestamp": ts,
    }


def _command_event(
    cowrie_sid: str,
    cmd: str,
    *,
    ts: str = "2026-05-22T10:00:05+00:00",
) -> dict[str, object]:
    return {
        "session": cowrie_sid,
        "eventid": "cowrie.command.input",
        "input": cmd,
        "response": f"{cmd}: ok",
        "timestamp": ts,
    }


def _closed_event(
    cowrie_sid: str,
    *,
    ts: str = "2026-05-22T10:00:30+00:00",
) -> dict[str, object]:
    return {
        "session": cowrie_sid,
        "eventid": "cowrie.session.closed",
        "timestamp": ts,
    }


async def test_imports_closed_session_with_turns(
    session_store: SessionStore,
    tmp_path: Path,
) -> None:
    path = tmp_path / "sessions.jsonl"
    path.write_text(
        _envelope(_connect_event("sess-1"))
        + _envelope(_command_event("sess-1", "whoami"))
        + _envelope(_command_event("sess-1", "id", ts="2026-05-22T10:00:06+00:00"))
        + _envelope(_closed_event("sess-1")),
        encoding="utf-8",
    )
    imported = await import_jsonl_into_store(path, session_store)
    assert imported == 1
    sessions = await session_store.get_active_sessions()
    # The session was closed during import, so it's not active.
    assert sessions == []
    stats = await session_store.get_stats()
    assert stats.total_commands_observed == 2


async def test_imports_set_session_command_count_to_turn_count(
    session_store: SessionStore,
    tmp_path: Path,
) -> None:
    """Regression: _write_accumulator used to upsert the snapshot with
    its full turns tuple AND then call record_turn for each turn,
    leaving sessions.command_count at 2 * N. The upsert now uses an
    empty turns tuple so the per-turn loop increments from 0 to N.
    """
    path = tmp_path / "sessions.jsonl"
    path.write_text(
        _envelope(_connect_event("sess-count"))
        + _envelope(_command_event("sess-count", "whoami"))
        + _envelope(_command_event("sess-count", "id", ts="2026-05-22T10:00:06+00:00"))
        + _envelope(_command_event("sess-count", "ls", ts="2026-05-22T10:00:07+00:00"))
        + _envelope(_closed_event("sess-count")),
        encoding="utf-8",
    )
    await import_jsonl_into_store(path, session_store)

    # SessionSnapshot does not expose command_count; read the column
    # directly. This is the operator-visible value that the CSV
    # export's `command_count` column reads.
    conn = session_store._conn
    assert conn is not None
    (count,) = conn.execute(
        "SELECT command_count FROM sessions WHERE source_ip = ?",
        ("203.0.113.7",),
    ).fetchone()
    assert count == 3


async def test_imports_open_session_as_active(
    session_store: SessionStore,
    tmp_path: Path,
) -> None:
    path = tmp_path / "sessions.jsonl"
    # No closed event; session is still open in the fallback.
    path.write_text(
        _envelope(_connect_event("sess-open")) + _envelope(_command_event("sess-open", "ls")),
        encoding="utf-8",
    )
    imported = await import_jsonl_into_store(path, session_store)
    assert imported == 1
    active = await session_store.get_active_sessions()
    assert len(active) == 1
    assert active[0].source_ip == "203.0.113.7"


async def test_skips_unrecognised_and_malformed_lines(
    session_store: SessionStore,
    tmp_path: Path,
) -> None:
    path = tmp_path / "sessions.jsonl"
    path.write_text(
        "this is not json\n"
        + _envelope({"session": "sess-2", "eventid": "cowrie.log.open"})  # ignored
        + _envelope(_connect_event("sess-2"))
        + _envelope(_command_event("sess-2", "uname"))
        + _envelope(_closed_event("sess-2"))
        + "\n",  # blank line
        encoding="utf-8",
    )
    imported = await import_jsonl_into_store(path, session_store)
    assert imported == 1


async def test_raises_when_file_missing(
    session_store: SessionStore,
    tmp_path: Path,
) -> None:
    missing = tmp_path / "does-not-exist.jsonl"
    with pytest.raises(FileNotFoundError):
        await import_jsonl_into_store(missing, session_store)


async def test_rejects_nonpositive_batch_size(
    session_store: SessionStore,
    tmp_path: Path,
) -> None:
    path = tmp_path / "sessions.jsonl"
    path.write_text("", encoding="utf-8")
    with pytest.raises(ValueError):
        await import_jsonl_into_store(path, session_store, batch_size=0)


async def test_batch_flush_keeps_open_sessions_in_progress(
    session_store: SessionStore,
    tmp_path: Path,
) -> None:
    """When the accumulator hits the cap, only CLOSED sessions are
    flushed; open ones stay in the working set until they close or
    the file ends. We verify by sending more than batch_size closed
    sessions interleaved with one open one."""
    path = tmp_path / "sessions.jsonl"
    lines: list[str] = []
    for i in range(5):
        sid = f"closed-{i}"
        lines.append(_envelope(_connect_event(sid)))
        lines.append(_envelope(_closed_event(sid)))
    # An open session at the end.
    lines.append(_envelope(_connect_event("still-open")))
    lines.append(_envelope(_command_event("still-open", "pwd")))
    path.write_text("".join(lines), encoding="utf-8")

    imported = await import_jsonl_into_store(path, session_store, batch_size=2)
    assert imported == 6
    active = await session_store.get_active_sessions()
    assert len(active) == 1  # the still-open one
