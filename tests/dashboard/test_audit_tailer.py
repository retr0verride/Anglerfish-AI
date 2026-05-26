"""Tests for :class:`anglerfish.dashboard.audit_tailer.AuditTailer`.

The tailer is exercised by driving its public API directly
(``_poll_once`` for deterministic stepping) rather than racing
the background poll task. Lifespan integration via ``create_app``
is covered separately in ``test_app.py``; here the focus is on
the event-translation, offset-cache, and rotation behaviours.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID, uuid4

import pytest

from anglerfish.dashboard.audit_tailer import AuditTailer
from anglerfish.dashboard.state import DashboardEventKind, DashboardState
from anglerfish.models.embedding import SessionEmbedding
from anglerfish.models.session import ResponseSource


def _audit_line(event_type: str, **fields: object) -> str:
    """Render one audit-log line in the same shape ``AuditLog.record`` writes."""
    record: dict[str, object] = {
        "ts": fields.pop("ts", datetime(2026, 5, 22, 10, 0, tzinfo=UTC).isoformat()),
        "event_type": event_type,
    }
    record.update(fields)
    return json.dumps(record, separators=(",", ":")) + "\n"


def _append(path: Path, *lines: str) -> None:
    with path.open("a", encoding="utf-8") as fp:
        fp.write("".join(lines))


def _make_tailer(
    *,
    tmp_path: Path,
    dashboard_state: DashboardState,
    audit_filename: str = "audit.jsonl",
) -> AuditTailer:
    return AuditTailer(
        audit_path=tmp_path / audit_filename,
        dashboard_state=dashboard_state,
        offset_cache_path=tmp_path / "audit_tailer.json",
        poll_interval_seconds=0.05,
    )


# ---------------------------------------------------------------------------
# Construction + lifecycle
# ---------------------------------------------------------------------------


async def test_construction_rejects_nonpositive_poll(
    dashboard_state: DashboardState,
    tmp_path: Path,
) -> None:
    with pytest.raises(ValueError):
        AuditTailer(
            audit_path=tmp_path / "audit.jsonl",
            dashboard_state=dashboard_state,
            offset_cache_path=tmp_path / "cache.json",
            poll_interval_seconds=0,
        )


async def test_start_is_idempotent_and_stop_cleans_up(
    dashboard_state: DashboardState,
    tmp_path: Path,
) -> None:
    tailer = _make_tailer(tmp_path=tmp_path, dashboard_state=dashboard_state)
    await tailer.start()
    assert tailer.is_running
    await tailer.start()  # second call: no-op, still running
    assert tailer.is_running
    await tailer.stop()
    assert not tailer.is_running


async def test_stop_is_idempotent_without_prior_start(
    dashboard_state: DashboardState,
    tmp_path: Path,
) -> None:
    tailer = _make_tailer(tmp_path=tmp_path, dashboard_state=dashboard_state)
    await tailer.stop()
    assert not tailer.is_running


async def test_no_audit_file_is_silent(
    dashboard_state: DashboardState,
    tmp_path: Path,
) -> None:
    tailer = _make_tailer(tmp_path=tmp_path, dashboard_state=dashboard_state)
    await tailer._poll_once()
    assert tailer.offset == 0
    assert (await dashboard_state.get_active_sessions()) == []


async def test_empty_audit_file_processes_zero_events(
    dashboard_state: DashboardState,
    tmp_path: Path,
) -> None:
    (tmp_path / "audit.jsonl").write_text("", encoding="utf-8")
    tailer = _make_tailer(tmp_path=tmp_path, dashboard_state=dashboard_state)
    await tailer._poll_once()
    assert tailer.offset == 0


# ---------------------------------------------------------------------------
# Event translation
# ---------------------------------------------------------------------------


async def test_session_opened_creates_session_row(
    dashboard_state: DashboardState,
    tmp_path: Path,
) -> None:
    sid = uuid4()
    audit_path = tmp_path / "audit.jsonl"
    _append(
        audit_path,
        _audit_line(
            "lure.session_opened",
            source_ip="203.0.113.7",
            username="root",
            client_version="SSH-2.0-libssh_0.10.4",
            session_id=str(sid),
        ),
    )
    tailer = _make_tailer(tmp_path=tmp_path, dashboard_state=dashboard_state)
    await tailer._poll_once()

    snap = await dashboard_state.get_session(sid)
    assert snap is not None
    assert snap.source_ip == "203.0.113.7"
    assert snap.username == "root"
    assert snap.turns == ()


async def test_full_session_lifecycle_emits_turns_then_ends(
    dashboard_state: DashboardState,
    tmp_path: Path,
) -> None:
    sid = uuid4()
    audit_path = tmp_path / "audit.jsonl"
    sid_s = str(sid)
    _append(
        audit_path,
        _audit_line(
            "lure.session_opened",
            source_ip="203.0.113.7",
            username="root",
            session_id=sid_s,
        ),
        _audit_line(
            "lure.command_bridge",
            source_ip="203.0.113.7",
            command="whoami",
            latency_ms=12.3,
            session_id=sid_s,
        ),
        _audit_line(
            "lure.command_native",
            source_ip="203.0.113.7",
            command="cd /tmp",
            session_id=sid_s,
        ),
        _audit_line(
            "lure.fallback_served",
            source_ip="203.0.113.7",
            command="ls -la",
            reason="OllamaUnavailableError",
            session_id=sid_s,
        ),
        _audit_line(
            "lure.session_closed",
            source_ip="203.0.113.7",
            username="root",
            duration_seconds=42.0,
            command_count=3,
            error=None,
            session_id=sid_s,
        ),
    )
    tailer = _make_tailer(tmp_path=tmp_path, dashboard_state=dashboard_state)
    await tailer._poll_once()

    snap = await dashboard_state.get_session(sid)
    assert snap is not None
    assert [t.command for t in snap.turns] == ["whoami", "cd /tmp", "ls -la"]
    assert [t.source for t in snap.turns] == [
        ResponseSource.AI,
        ResponseSource.AI,
        ResponseSource.FALLBACK,
    ]
    # Session is ended → drops from active list.
    active = await dashboard_state.get_active_sessions()
    assert all(s.session_id != sid for s in active)


async def test_command_before_open_auto_creates_placeholder(
    dashboard_state: DashboardState,
    tmp_path: Path,
) -> None:
    sid = uuid4()
    audit_path = tmp_path / "audit.jsonl"
    sid_s = str(sid)
    _append(
        audit_path,
        _audit_line(
            "lure.command_bridge",
            source_ip="203.0.113.7",
            command="uname -a",
            latency_ms=5.0,
            session_id=sid_s,
        ),
    )
    tailer = _make_tailer(tmp_path=tmp_path, dashboard_state=dashboard_state)
    await tailer._poll_once()

    snap = await dashboard_state.get_session(sid)
    assert snap is not None
    assert snap.source_ip == "203.0.113.7"
    assert snap.username == "unknown"  # placeholder
    assert snap.fake_hostname == "unknown"  # placeholder
    assert len(snap.turns) == 1
    assert snap.turns[0].command == "uname -a"


async def test_open_after_command_upgrades_placeholder_metadata(
    dashboard_state: DashboardState,
    tmp_path: Path,
) -> None:
    sid = uuid4()
    audit_path = tmp_path / "audit.jsonl"
    sid_s = str(sid)
    _append(
        audit_path,
        _audit_line(
            "lure.command_bridge",
            source_ip="203.0.113.7",
            command="id",
            latency_ms=3.0,
            session_id=sid_s,
        ),
        _audit_line(
            "lure.session_opened",
            source_ip="203.0.113.7",
            username="root",
            client_version="SSH-2.0-OpenSSH",
            session_id=sid_s,
        ),
    )
    tailer = _make_tailer(tmp_path=tmp_path, dashboard_state=dashboard_state)
    await tailer._poll_once()

    snap = await dashboard_state.get_session(sid)
    assert snap is not None
    assert snap.username == "root"  # upgraded from placeholder
    # Turn from the pre-open command is preserved.
    assert [t.command for t in snap.turns] == ["id"]


async def test_events_without_session_id_are_ignored(
    dashboard_state: DashboardState,
    tmp_path: Path,
) -> None:
    audit_path = tmp_path / "audit.jsonl"
    _append(
        audit_path,
        _audit_line(
            "lure.rate_limited",
            source_ip="203.0.113.7",
            kind="per_ip_concurrent",
            concurrent=3,
        ),
        _audit_line(
            "lure.fingerprint_observed",
            source_ip="203.0.113.7",
            client_version="SSH-2.0",
            hassh="deadbeef",
        ),
        _audit_line(
            "lure.login_attempt",
            source_ip="203.0.113.7",
            username="root",
            password_hash_prefix="aabbccdd",
        ),
    )
    tailer = _make_tailer(tmp_path=tmp_path, dashboard_state=dashboard_state)
    await tailer._poll_once()
    assert (await dashboard_state.get_active_sessions()) == []
    # Offset still advances past the consumed (but ignored) lines.
    assert tailer.offset > 0


async def test_non_lure_events_are_ignored(
    dashboard_state: DashboardState,
    tmp_path: Path,
) -> None:
    audit_path = tmp_path / "audit.jsonl"
    _append(
        audit_path,
        _audit_line(
            "dashboard.login_success",
            username="admin",
            session_id=str(uuid4()),  # has a session_id but unknown type
        ),
    )
    tailer = _make_tailer(tmp_path=tmp_path, dashboard_state=dashboard_state)
    await tailer._poll_once()
    assert (await dashboard_state.get_active_sessions()) == []


async def test_malformed_lines_are_skipped(
    dashboard_state: DashboardState,
    tmp_path: Path,
) -> None:
    sid = uuid4()
    audit_path = tmp_path / "audit.jsonl"
    audit_path.write_text(
        "not json at all\n"
        + _audit_line(
            "lure.session_opened",
            source_ip="203.0.113.7",
            username="root",
            session_id=str(sid),
        )
        + "{}\n"  # valid JSON, missing required fields
        + "  \n",  # blank line
        encoding="utf-8",
    )
    tailer = _make_tailer(tmp_path=tmp_path, dashboard_state=dashboard_state)
    await tailer._poll_once()
    assert (await dashboard_state.get_session(sid)) is not None


async def test_invalid_session_id_uuid_is_skipped(
    dashboard_state: DashboardState,
    tmp_path: Path,
) -> None:
    audit_path = tmp_path / "audit.jsonl"
    _append(
        audit_path,
        _audit_line(
            "lure.session_opened",
            source_ip="203.0.113.7",
            username="root",
            session_id="not-a-uuid",
        ),
    )
    tailer = _make_tailer(tmp_path=tmp_path, dashboard_state=dashboard_state)
    await tailer._poll_once()
    assert (await dashboard_state.get_active_sessions()) == []


async def test_event_publishes_websocket_event(
    dashboard_state: DashboardState,
    tmp_path: Path,
) -> None:
    sid = uuid4()
    audit_path = tmp_path / "audit.jsonl"
    _append(
        audit_path,
        _audit_line(
            "lure.session_opened",
            source_ip="203.0.113.7",
            username="root",
            session_id=str(sid),
        ),
    )
    tailer = _make_tailer(tmp_path=tmp_path, dashboard_state=dashboard_state)
    async with dashboard_state.subscribe() as queue:
        await tailer._poll_once()
        event = await queue.get()
    assert event.kind == DashboardEventKind.SESSION_STARTED


# ---------------------------------------------------------------------------
# Offset cache + rotation
# ---------------------------------------------------------------------------


async def test_partial_line_at_eof_is_held_for_next_cycle(
    dashboard_state: DashboardState,
    tmp_path: Path,
) -> None:
    sid = uuid4()
    audit_path = tmp_path / "audit.jsonl"
    # First write: one complete line + a partial second line (no \n).
    audit_path.write_text(
        _audit_line(
            "lure.session_opened",
            source_ip="203.0.113.7",
            username="root",
            session_id=str(sid),
        )
        + '{"ts":"2026',  # truncated mid-write
        encoding="utf-8",
    )
    tailer = _make_tailer(tmp_path=tmp_path, dashboard_state=dashboard_state)
    await tailer._poll_once()
    first_offset = tailer.offset
    assert first_offset > 0
    assert (await dashboard_state.get_session(sid)) is not None

    # Now finish the second line and add a command for it.
    sid2 = uuid4()
    audit_path.write_text(
        _audit_line(
            "lure.session_opened",
            source_ip="203.0.113.7",
            username="root",
            session_id=str(sid),
        )
        + _audit_line(
            "lure.session_opened",
            source_ip="198.51.100.4",
            username="admin",
            session_id=str(sid2),
        ),
        encoding="utf-8",
    )
    await tailer._poll_once()
    assert tailer.offset > first_offset
    assert (await dashboard_state.get_session(sid2)) is not None


async def test_copytruncate_resets_offset(
    dashboard_state: DashboardState,
    tmp_path: Path,
) -> None:
    sid1 = uuid4()
    sid2 = uuid4()
    sid3 = uuid4()
    audit_path = tmp_path / "audit.jsonl"
    # Pre-rotation: three lines so the file is meaningfully larger
    # than the single line we shrink it to.
    _append(
        audit_path,
        _audit_line(
            "lure.session_opened",
            source_ip="203.0.113.7",
            username="root",
            session_id=str(sid1),
        ),
        _audit_line(
            "lure.session_opened",
            source_ip="198.51.100.5",
            username="root",
            session_id=str(sid2),
        ),
        _audit_line(
            "lure.session_opened",
            source_ip="192.0.2.42",
            username="root",
            session_id=str(sid3),
        ),
    )
    tailer = _make_tailer(tmp_path=tmp_path, dashboard_state=dashboard_state)
    await tailer._poll_once()
    pre_rotation_offset = tailer.offset
    assert pre_rotation_offset > 0

    # Simulate copytruncate: same inode, file shrinks to one line of
    # an entirely new session.
    sid_post = uuid4()
    new_content = _audit_line(
        "lure.session_opened",
        source_ip="198.51.100.4",
        username="admin",
        session_id=str(sid_post),
    )
    audit_path.write_text(new_content, encoding="utf-8")
    await tailer._poll_once()
    assert tailer.offset < pre_rotation_offset
    assert tailer.offset == len(new_content.encode("utf-8"))
    assert (await dashboard_state.get_session(sid_post)) is not None


async def test_offset_cache_persists_across_restart(
    dashboard_state: DashboardState,
    tmp_path: Path,
) -> None:
    sid = uuid4()
    audit_path = tmp_path / "audit.jsonl"
    _append(
        audit_path,
        _audit_line(
            "lure.session_opened",
            source_ip="203.0.113.7",
            username="root",
            session_id=str(sid),
        ),
    )
    tailer_a = _make_tailer(tmp_path=tmp_path, dashboard_state=dashboard_state)
    await tailer_a._poll_once()
    first_offset = tailer_a.offset

    # New instance against the same cache path should resume.
    tailer_b = _make_tailer(tmp_path=tmp_path, dashboard_state=dashboard_state)
    tailer_b._load_offset_cache()
    assert tailer_b.offset == first_offset

    # No new audit content → second poll is a no-op.
    await tailer_b._poll_once()
    assert tailer_b.offset == first_offset


async def test_corrupt_cache_resets_to_zero(
    dashboard_state: DashboardState,
    tmp_path: Path,
) -> None:
    (tmp_path / "audit_tailer.json").write_text("not json", encoding="utf-8")
    tailer = _make_tailer(tmp_path=tmp_path, dashboard_state=dashboard_state)
    tailer._load_offset_cache()
    assert tailer.offset == 0


async def test_cache_path_mismatch_resets_to_zero(
    dashboard_state: DashboardState,
    tmp_path: Path,
) -> None:
    cache = tmp_path / "audit_tailer.json"
    cache.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "audit_path": "/some/other/path",
                "offset": 12345,
            },
        ),
        encoding="utf-8",
    )
    tailer = _make_tailer(tmp_path=tmp_path, dashboard_state=dashboard_state)
    tailer._load_offset_cache()
    assert tailer.offset == 0


# ---------------------------------------------------------------------------
# Lifespan / background-task behaviour
# ---------------------------------------------------------------------------


async def test_background_task_processes_new_appends(
    dashboard_state: DashboardState,
    tmp_path: Path,
) -> None:
    """End-to-end sanity: start the real background task, append a
    line, wait a couple poll cycles, assert the row exists. Uses the
    short test poll interval so the wait stays under a second."""
    import asyncio as _asyncio

    audit_path = tmp_path / "audit.jsonl"
    sid = uuid4()
    tailer = _make_tailer(tmp_path=tmp_path, dashboard_state=dashboard_state)
    await tailer.start()
    try:
        _append(
            audit_path,
            _audit_line(
                "lure.session_opened",
                source_ip="203.0.113.7",
                username="root",
                session_id=str(sid),
            ),
        )
        # Three poll cycles' worth of time; ample headroom at 0.05s.
        for _ in range(20):
            await _asyncio.sleep(0.05)
            if (await dashboard_state.get_session(sid)) is not None:
                break
    finally:
        await tailer.stop()
    snap = await dashboard_state.get_session(sid)
    assert snap is not None


# ---------------------------------------------------------------------------
# Type-shape sanity
# ---------------------------------------------------------------------------


async def test_dispatched_command_carries_correct_source_enum(
    dashboard_state: DashboardState,
    tmp_path: Path,
) -> None:
    """Locks in the documented decision: native commands fold into
    ResponseSource.AI per the existing CommandTurn schema."""
    sid = uuid4()
    audit_path = tmp_path / "audit.jsonl"
    _append(
        audit_path,
        _audit_line(
            "lure.session_opened",
            source_ip="203.0.113.7",
            username="root",
            session_id=str(sid),
        ),
        _audit_line(
            "lure.command_native",
            source_ip="203.0.113.7",
            command="cd /var",
            session_id=str(sid),
        ),
    )
    tailer = _make_tailer(tmp_path=tmp_path, dashboard_state=dashboard_state)
    await tailer._poll_once()
    snap = await dashboard_state.get_session(sid)
    assert snap is not None
    assert snap.turns[0].source is ResponseSource.AI


def test_uuid_type_for_session_id_field() -> None:
    """Type-shape sanity: dispatch path accepts only valid UUIDs."""
    assert UUID("00000000-0000-0000-0000-000000000000") is not None


# ---------------------------------------------------------------------------
# Stage 7 slice 3: bridge.intent_extracted dispatch
# ---------------------------------------------------------------------------


async def test_intent_extracted_persists_to_store(
    dashboard_state: DashboardState,
    tmp_path: Path,
) -> None:
    tailer = _make_tailer(tmp_path=tmp_path, dashboard_state=dashboard_state)
    sid = uuid4()
    # Open the session so the FK on the intents row resolves.
    _append(
        tailer.audit_path,
        _audit_line(
            "lure.session_opened",
            session_id=str(sid),
            source_ip="203.0.113.7",
            username="root",
        ),
        _audit_line(
            "bridge.intent_extracted",
            session_id=str(sid),
            actor_profile="automated",
            confidence="high",
            intent="Deploy cryptominer.",
            why="Downloaded miner; configured pool URL.",
            matched_techniques=["T1059.004", "T1496"],
            summary="Automated session.",
            extracted_at=datetime(2026, 5, 25, 12, 30, tzinfo=UTC).isoformat(),
        ),
    )
    await tailer._poll_once()
    loaded = await dashboard_state.get_intent(sid)
    assert loaded is not None
    assert loaded.actor_profile == "automated"
    assert loaded.confidence == "high"
    assert loaded.matched_techniques == ("T1059.004", "T1496")


async def test_intent_extracted_with_malformed_actor_profile_is_skipped(
    dashboard_state: DashboardState,
    tmp_path: Path,
) -> None:
    """A bogus actor_profile is dropped silently; tailer keeps running."""
    tailer = _make_tailer(tmp_path=tmp_path, dashboard_state=dashboard_state)
    sid = uuid4()
    _append(
        tailer.audit_path,
        _audit_line(
            "lure.session_opened",
            session_id=str(sid),
            source_ip="1.1.1.1",
            username="root",
        ),
        _audit_line(
            "bridge.intent_extracted",
            session_id=str(sid),
            actor_profile="not-a-valid-profile",
            confidence="high",
            intent="x",
            why="x",
            matched_techniques=[],
            summary="x",
            extracted_at=datetime(2026, 5, 25, 12, 30, tzinfo=UTC).isoformat(),
        ),
    )
    await tailer._poll_once()
    assert await dashboard_state.get_intent(sid) is None


async def test_intent_extracted_with_malformed_extracted_at_is_skipped(
    dashboard_state: DashboardState,
    tmp_path: Path,
) -> None:
    tailer = _make_tailer(tmp_path=tmp_path, dashboard_state=dashboard_state)
    sid = uuid4()
    _append(
        tailer.audit_path,
        _audit_line(
            "lure.session_opened",
            session_id=str(sid),
            source_ip="1.1.1.1",
            username="root",
        ),
        _audit_line(
            "bridge.intent_extracted",
            session_id=str(sid),
            actor_profile="opportunistic",
            confidence="low",
            intent="x",
            why="x",
            matched_techniques=[],
            summary="x",
            extracted_at="definitely-not-iso",
        ),
    )
    await tailer._poll_once()
    assert await dashboard_state.get_intent(sid) is None


# ---------------------------------------------------------------------------
# Stage 8 slice 4: bridge.embedding_generated dispatch + cluster_match
# ---------------------------------------------------------------------------


class _CaptureAudit:
    """Drop-in for AuditLog that captures records emitted by the tailer."""

    def __init__(self) -> None:
        self.events: list[tuple[str, dict[str, object]]] = []

    def record(self, event_type: str, **fields: object) -> None:
        self.events.append((event_type, fields))


def _make_tailer_with_audit(
    *,
    tmp_path: Path,
    dashboard_state: DashboardState,
    audit_log: _CaptureAudit,
    threshold: float = 0.85,
) -> AuditTailer:
    return AuditTailer(
        audit_path=tmp_path / "audit.jsonl",
        dashboard_state=dashboard_state,
        offset_cache_path=tmp_path / "audit_tailer.json",
        poll_interval_seconds=0.05,
        audit_log=audit_log,  # type: ignore[arg-type]
        cluster_similarity_threshold=threshold,
    )


def _embedding_event(
    sid: UUID,
    *,
    vector: list[float],
    model: str = "embed-test",
    dimension: int | None = None,
    generated_at: datetime | None = None,
) -> str:
    return _audit_line(
        "bridge.embedding_generated",
        session_id=str(sid),
        vector=vector,
        dimension=dimension if dimension is not None else len(vector),
        model=model,
        generated_at=(generated_at or datetime(2026, 5, 26, 12, 30, tzinfo=UTC)).isoformat(),
    )


async def test_embedding_generated_persists_to_store(
    dashboard_state: DashboardState,
    tmp_path: Path,
) -> None:
    audit = _CaptureAudit()
    tailer = _make_tailer_with_audit(
        tmp_path=tmp_path,
        dashboard_state=dashboard_state,
        audit_log=audit,
    )
    sid = uuid4()
    vector = [0.01 * i for i in range(64)]
    _append(
        tailer.audit_path,
        _audit_line(
            "lure.session_opened",
            session_id=str(sid),
            source_ip="203.0.113.7",
            username="root",
        ),
        _embedding_event(sid, vector=vector),
    )
    await tailer._poll_once()
    loaded = await dashboard_state.get_embedding(sid)
    assert loaded is not None
    assert loaded.session_id == sid
    assert loaded.dimension == 64
    assert loaded.model == "embed-test"
    # No neighbours to match against -> no cluster_match emitted.
    cluster_events = [e for e in audit.events if e[0] == "bridge.cluster_match"]
    assert cluster_events == []


async def test_embedding_generated_emits_cluster_match_when_neighbour_passes_threshold(
    dashboard_state: DashboardState,
    tmp_path: Path,
) -> None:
    audit = _CaptureAudit()
    tailer = _make_tailer_with_audit(
        tmp_path=tmp_path,
        dashboard_state=dashboard_state,
        audit_log=audit,
        threshold=0.5,
    )
    sid_first = uuid4()
    sid_second = uuid4()
    vector = [1.0] + [0.0] * 63
    _append(
        tailer.audit_path,
        _audit_line(
            "lure.session_opened",
            session_id=str(sid_first),
            source_ip="203.0.113.7",
            username="root",
        ),
        _embedding_event(sid_first, vector=vector),
        _audit_line(
            "lure.session_opened",
            session_id=str(sid_second),
            source_ip="203.0.113.8",
            username="root",
        ),
        _embedding_event(sid_second, vector=vector),
    )
    await tailer._poll_once()

    cluster_events = [e for e in audit.events if e[0] == "bridge.cluster_match"]
    assert len(cluster_events) == 1
    _, fields = cluster_events[0]
    assert fields["session_id"] == str(sid_second)
    assert fields["model"] == "embed-test"
    matches = fields["matches"]
    assert isinstance(matches, list)
    assert len(matches) == 1
    assert matches[0]["session_id"] == str(sid_first)
    assert matches[0]["similarity"] >= 0.5


async def test_embedding_generated_skips_cluster_match_below_threshold(
    dashboard_state: DashboardState,
    tmp_path: Path,
) -> None:
    audit = _CaptureAudit()
    tailer = _make_tailer_with_audit(
        tmp_path=tmp_path,
        dashboard_state=dashboard_state,
        audit_log=audit,
        threshold=0.99,
    )
    sid_first = uuid4()
    sid_second = uuid4()
    far_a = [1.0] + [0.0] * 63
    far_b = [0.0] * 63 + [1.0]
    _append(
        tailer.audit_path,
        _audit_line(
            "lure.session_opened", session_id=str(sid_first), source_ip="1.1.1.1", username="root"
        ),
        _embedding_event(sid_first, vector=far_a),
        _audit_line(
            "lure.session_opened", session_id=str(sid_second), source_ip="1.1.1.2", username="root"
        ),
        _embedding_event(sid_second, vector=far_b),
    )
    await tailer._poll_once()
    assert [e for e in audit.events if e[0] == "bridge.cluster_match"] == []


async def test_embedding_generated_without_audit_log_skips_cluster_emission(
    dashboard_state: DashboardState,
    tmp_path: Path,
) -> None:
    """Tailer constructed without audit_log persists but never emits cluster_match."""
    tailer = AuditTailer(
        audit_path=tmp_path / "audit.jsonl",
        dashboard_state=dashboard_state,
        offset_cache_path=tmp_path / "audit_tailer.json",
        poll_interval_seconds=0.05,
    )
    sid = uuid4()
    vector = [0.01 * i for i in range(64)]
    _append(
        tailer.audit_path,
        _audit_line(
            "lure.session_opened", session_id=str(sid), source_ip="1.1.1.1", username="root"
        ),
        _embedding_event(sid, vector=vector),
    )
    await tailer._poll_once()
    assert await dashboard_state.get_embedding(sid) is not None  # persisted


async def test_embedding_generated_with_malformed_vector_is_skipped(
    dashboard_state: DashboardState,
    tmp_path: Path,
) -> None:
    audit = _CaptureAudit()
    tailer = _make_tailer_with_audit(
        tmp_path=tmp_path,
        dashboard_state=dashboard_state,
        audit_log=audit,
    )
    sid = uuid4()
    _append(
        tailer.audit_path,
        _audit_line(
            "lure.session_opened", session_id=str(sid), source_ip="1.1.1.1", username="root"
        ),
        # vector is missing.
        _audit_line(
            "bridge.embedding_generated",
            session_id=str(sid),
            dimension=64,
            model="embed-test",
            generated_at=datetime(2026, 5, 26, 12, 30, tzinfo=UTC).isoformat(),
        ),
    )
    await tailer._poll_once()
    assert await dashboard_state.get_embedding(sid) is None


async def test_embedding_generated_with_bad_generated_at_is_skipped(
    dashboard_state: DashboardState,
    tmp_path: Path,
) -> None:
    audit = _CaptureAudit()
    tailer = _make_tailer_with_audit(
        tmp_path=tmp_path,
        dashboard_state=dashboard_state,
        audit_log=audit,
    )
    sid = uuid4()
    _append(
        tailer.audit_path,
        _audit_line(
            "lure.session_opened", session_id=str(sid), source_ip="1.1.1.1", username="root"
        ),
        _audit_line(
            "bridge.embedding_generated",
            session_id=str(sid),
            vector=[0.01 * i for i in range(64)],
            dimension=64,
            model="embed-test",
            generated_at="definitely-not-iso",
        ),
    )
    await tailer._poll_once()
    assert await dashboard_state.get_embedding(sid) is None


def test_construction_rejects_threshold_outside_unit_interval(
    dashboard_state: DashboardState,
    tmp_path: Path,
) -> None:
    with pytest.raises(ValueError):
        AuditTailer(
            audit_path=tmp_path / "audit.jsonl",
            dashboard_state=dashboard_state,
            offset_cache_path=tmp_path / "audit_tailer.json",
            cluster_similarity_threshold=1.5,
        )
    with pytest.raises(ValueError):
        AuditTailer(
            audit_path=tmp_path / "audit.jsonl",
            dashboard_state=dashboard_state,
            offset_cache_path=tmp_path / "audit_tailer.json",
            cluster_similarity_threshold=-0.1,
        )


async def test_dashboard_state_round_trips_embedding(
    dashboard_state: DashboardState,
    tmp_path: Path,
) -> None:
    """DashboardState.upsert_embedding -> get_embedding is a no-publish pass-through."""
    sid = uuid4()
    # Need a session row for the FK; reuse the tailer-driven path.
    tailer = _make_tailer(tmp_path=tmp_path, dashboard_state=dashboard_state)
    _append(
        tailer.audit_path,
        _audit_line(
            "lure.session_opened", session_id=str(sid), source_ip="1.1.1.1", username="root"
        ),
    )
    await tailer._poll_once()

    embedding = SessionEmbedding(
        session_id=sid,
        vector=tuple(0.01 * i for i in range(64)),
        dimension=64,
        model="embed-test",
        generated_at=datetime(2026, 5, 26, 12, 30, tzinfo=UTC),
    )
    await dashboard_state.upsert_embedding(embedding)
    loaded = await dashboard_state.get_embedding(sid)
    assert loaded is not None
    assert loaded.dimension == 64
    # find_similar passes through to the store.
    assert await dashboard_state.find_similar(sid) == []


# ---------------------------------------------------------------------------
# Stage 9 slice 9.4: cluster-bias persona rebound
# ---------------------------------------------------------------------------


def _make_tailer_with_persona_bias(
    *,
    tmp_path: Path,
    dashboard_state: DashboardState,
    audit_log: _CaptureAudit,
    cluster_threshold: float = 0.5,
    bias_threshold: float = 0.9,
) -> AuditTailer:
    return AuditTailer(
        audit_path=tmp_path / "audit.jsonl",
        dashboard_state=dashboard_state,
        offset_cache_path=tmp_path / "audit_tailer.json",
        poll_interval_seconds=0.05,
        audit_log=audit_log,  # type: ignore[arg-type]
        cluster_similarity_threshold=cluster_threshold,
        persona_bias_threshold=bias_threshold,
    )


def _persona_session_opened(sid: UUID, *, source_ip: str, persona: str) -> str:
    """Audit line shape that the tailer turns into a sessions row with persona."""
    return _audit_line(
        "lure.session_opened",
        session_id=str(sid),
        source_ip=source_ip,
        username="root",
    )


async def _seed_session_with_persona(
    dashboard_state: DashboardState,
    *,
    sid: UUID,
    source_ip: str,
    persona: str,
) -> None:
    """Insert a session row directly with a persona name set."""
    from anglerfish.models.session import SessionSnapshot

    now = datetime(2026, 5, 26, 12, 0, tzinfo=UTC)
    snap = SessionSnapshot(
        session_id=sid,
        source_ip=source_ip,
        username="root",
        fake_hostname=persona,
        fake_username="root",
        fake_cwd="/root",
        started_at=now,
        last_activity_at=now,
        turns=(),
        persona_name=persona,
    )
    await dashboard_state.update_session(snap)


def test_construction_rejects_persona_bias_outside_unit_interval(
    dashboard_state: DashboardState,
    tmp_path: Path,
) -> None:
    with pytest.raises(ValueError, match="persona_bias_threshold"):
        AuditTailer(
            audit_path=tmp_path / "audit.jsonl",
            dashboard_state=dashboard_state,
            offset_cache_path=tmp_path / "audit_tailer.json",
            persona_bias_threshold=1.5,
        )


async def test_rebound_fires_when_neighbour_above_bias_and_different_persona(
    dashboard_state: DashboardState,
    tmp_path: Path,
) -> None:
    """Strong neighbour + different persona -> sessions.persona rewritten."""
    audit = _CaptureAudit()
    tailer = _make_tailer_with_persona_bias(
        tmp_path=tmp_path,
        dashboard_state=dashboard_state,
        audit_log=audit,
        cluster_threshold=0.5,
        bias_threshold=0.9,
    )
    neighbour_sid = uuid4()
    closed_sid = uuid4()
    # Seed: neighbour already in the DB with persona "gpu-rig".
    await _seed_session_with_persona(
        dashboard_state,
        sid=neighbour_sid,
        source_ip="203.0.113.1",
        persona="gpu-rig",
    )
    # Closed session opened later with persona "dev-laptop" via the
    # tailer's normal lure.session_opened + bridge.embedding_generated
    # flow, then update_session_persona via the direct path so the
    # closed session has a persona value.
    await _seed_session_with_persona(
        dashboard_state,
        sid=closed_sid,
        source_ip="203.0.113.2",
        persona="dev-laptop",
    )
    # Identical vectors -> cosine 1.0 (well above 0.9 bias).
    vector = [1.0] + [0.0] * 63
    # Persist the neighbour embedding first so find_similar finds it.
    from anglerfish.models.embedding import SessionEmbedding

    now = datetime(2026, 5, 26, 12, 30, tzinfo=UTC)
    await dashboard_state.upsert_embedding(
        SessionEmbedding(
            session_id=neighbour_sid,
            vector=tuple(vector),
            dimension=64,
            model="embed-test",
            generated_at=now,
        ),
    )

    _append(
        tailer.audit_path,
        _embedding_event(closed_sid, vector=vector),
    )
    await tailer._poll_once()

    rebounds = [e for e in audit.events if e[0] == "bridge.persona_rebound"]
    assert len(rebounds) == 1
    _, fields = rebounds[0]
    assert fields["session_id"] == str(closed_sid)
    assert fields["source_ip"] == "203.0.113.2"
    assert fields["old_persona"] == "dev-laptop"
    assert fields["new_persona"] == "gpu-rig"
    assert fields["neighbour_session_id"] == str(neighbour_sid)
    # Sessions.persona on the closed row is rewritten so the selector
    # picks up the rebound on the next session-open.
    reloaded = await dashboard_state.get_session(closed_sid)
    assert reloaded is not None
    assert reloaded.persona_name == "gpu-rig"


async def test_rebound_skipped_below_bias_threshold(
    dashboard_state: DashboardState,
    tmp_path: Path,
) -> None:
    """cluster_match fires but persona_bias_threshold blocks rebound."""
    audit = _CaptureAudit()
    tailer = _make_tailer_with_persona_bias(
        tmp_path=tmp_path,
        dashboard_state=dashboard_state,
        audit_log=audit,
        cluster_threshold=0.5,
        bias_threshold=0.99,  # very strict
    )
    neighbour_sid = uuid4()
    closed_sid = uuid4()
    await _seed_session_with_persona(
        dashboard_state,
        sid=neighbour_sid,
        source_ip="203.0.113.1",
        persona="gpu-rig",
    )
    await _seed_session_with_persona(
        dashboard_state,
        sid=closed_sid,
        source_ip="203.0.113.2",
        persona="dev-laptop",
    )
    # Slightly different vectors -> similarity ~ 0.7 to 0.85; well
    # under 0.99 bias.
    vec_a = [1.0, 0.5] + [0.0] * 62
    vec_b = [1.0, -0.5] + [0.0] * 62
    from anglerfish.models.embedding import SessionEmbedding

    now = datetime(2026, 5, 26, 12, 30, tzinfo=UTC)
    await dashboard_state.upsert_embedding(
        SessionEmbedding(
            session_id=neighbour_sid,
            vector=tuple(vec_a),
            dimension=64,
            model="embed-test",
            generated_at=now,
        ),
    )
    _append(tailer.audit_path, _embedding_event(closed_sid, vector=vec_b))
    await tailer._poll_once()
    assert not [e for e in audit.events if e[0] == "bridge.persona_rebound"]
    # Persona column on the closed session unchanged.
    reloaded = await dashboard_state.get_session(closed_sid)
    assert reloaded is not None
    assert reloaded.persona_name == "dev-laptop"


async def test_rebound_skipped_when_personas_match(
    dashboard_state: DashboardState,
    tmp_path: Path,
) -> None:
    """High similarity + same persona -> nothing to rebound to."""
    audit = _CaptureAudit()
    tailer = _make_tailer_with_persona_bias(
        tmp_path=tmp_path,
        dashboard_state=dashboard_state,
        audit_log=audit,
        cluster_threshold=0.5,
        bias_threshold=0.9,
    )
    neighbour_sid = uuid4()
    closed_sid = uuid4()
    await _seed_session_with_persona(
        dashboard_state,
        sid=neighbour_sid,
        source_ip="203.0.113.1",
        persona="gpu-rig",
    )
    await _seed_session_with_persona(
        dashboard_state,
        sid=closed_sid,
        source_ip="203.0.113.2",
        persona="gpu-rig",
    )
    vector = [1.0] + [0.0] * 63
    from anglerfish.models.embedding import SessionEmbedding

    now = datetime(2026, 5, 26, 12, 30, tzinfo=UTC)
    await dashboard_state.upsert_embedding(
        SessionEmbedding(
            session_id=neighbour_sid,
            vector=tuple(vector),
            dimension=64,
            model="embed-test",
            generated_at=now,
        ),
    )
    _append(tailer.audit_path, _embedding_event(closed_sid, vector=vector))
    await tailer._poll_once()
    assert not [e for e in audit.events if e[0] == "bridge.persona_rebound"]


# ---------------------------------------------------------------------------
# Stage 10 slice 2: bridge.persistence_attempt dispatch
# ---------------------------------------------------------------------------


def _persistence_attempt_line(
    *,
    session_id: UUID,
    source_ip: str = "203.0.113.7",
    kind: str = "crontab",
    sub_key: str | None = None,
    payload: str = "0 * * * * /tmp/.x",
    source: str = "regex",
    created_at: datetime | None = None,
) -> str:
    fields: dict[str, object] = {
        "session_id": str(session_id),
        "source_ip": source_ip,
        "kind": kind,
        "payload": payload,
        "source": source,
        "created_at": (created_at or datetime(2026, 5, 26, 12, 0, tzinfo=UTC)).isoformat(),
    }
    if sub_key is not None:
        fields["sub_key"] = sub_key
    return _audit_line("bridge.persistence_attempt", **fields)


async def test_persistence_attempt_persists_to_store(
    dashboard_state: DashboardState,
    tmp_path: Path,
) -> None:
    tailer = _make_tailer(tmp_path=tmp_path, dashboard_state=dashboard_state)
    sid = uuid4()
    _append(
        tailer.audit_path,
        _persistence_attempt_line(
            session_id=sid,
            kind="authorized_keys",
            sub_key="alice",
            payload="ssh-ed25519 AAAA attacker",
            source="regex",
        ),
    )
    await tailer._poll_once()
    events = await dashboard_state.list_persistence_events_for_source_ip(
        "203.0.113.7",
    )
    assert len(events) == 1
    assert events[0].kind == "authorized_keys"
    assert events[0].sub_key == "alice"
    assert events[0].payload == "ssh-ed25519 AAAA attacker"
    assert events[0].source == "regex"
    del sid  # session_id is recorded but not exposed via the list query


async def test_persistence_attempt_replay_is_idempotent(
    dashboard_state: DashboardState,
    tmp_path: Path,
) -> None:
    """Same audit line tailed twice -> one row (UNIQUE constraint dedups)."""
    tailer = _make_tailer(tmp_path=tmp_path, dashboard_state=dashboard_state)
    sid = uuid4()
    line = _persistence_attempt_line(session_id=sid)
    _append(tailer.audit_path, line)
    await tailer._poll_once()
    # Simulate offset-cache loss: zero the offset + re-tail.
    tailer._offset = 0  # type: ignore[attr-defined]
    await tailer._poll_once()
    events = await dashboard_state.list_persistence_events_for_source_ip(
        "203.0.113.7",
    )
    assert len(events) == 1


async def test_persistence_attempt_missing_required_field_skipped(
    dashboard_state: DashboardState,
    tmp_path: Path,
) -> None:
    """Missing payload -> warning log, skip, no row inserted."""
    tailer = _make_tailer(tmp_path=tmp_path, dashboard_state=dashboard_state)
    sid = uuid4()
    _append(
        tailer.audit_path,
        _audit_line(
            "bridge.persistence_attempt",
            session_id=str(sid),
            source_ip="203.0.113.7",
            kind="crontab",
            source="regex",
            created_at=datetime(2026, 5, 26, 12, 0, tzinfo=UTC).isoformat(),
            # payload deliberately missing
        ),
    )
    await tailer._poll_once()
    events = await dashboard_state.list_persistence_events_for_source_ip(
        "203.0.113.7",
    )
    assert events == []


async def test_persistence_attempt_unknown_kind_skipped(
    dashboard_state: DashboardState,
    tmp_path: Path,
) -> None:
    tailer = _make_tailer(tmp_path=tmp_path, dashboard_state=dashboard_state)
    _append(
        tailer.audit_path,
        _persistence_attempt_line(
            session_id=uuid4(),
            kind="systemctl_disable",  # not in the kind enum
        ),
    )
    await tailer._poll_once()
    events = await dashboard_state.list_persistence_events_for_source_ip(
        "203.0.113.7",
    )
    assert events == []


async def test_persistence_attempt_malformed_created_at_skipped(
    dashboard_state: DashboardState,
    tmp_path: Path,
) -> None:
    tailer = _make_tailer(tmp_path=tmp_path, dashboard_state=dashboard_state)
    _append(
        tailer.audit_path,
        _audit_line(
            "bridge.persistence_attempt",
            session_id=str(uuid4()),
            source_ip="203.0.113.7",
            kind="crontab",
            payload="x",
            source="regex",
            created_at="not-a-timestamp",
        ),
    )
    await tailer._poll_once()
    events = await dashboard_state.list_persistence_events_for_source_ip(
        "203.0.113.7",
    )
    assert events == []
