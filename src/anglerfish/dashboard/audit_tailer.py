"""Audit-log tailer that wires bridge + lure events into the persistent stores.

Background asyncio task. Runs in the dashboard process. Reads the
append-only audit JSONL at ``settings.audit.log_path`` and dispatches
each recognised event to :class:`DashboardState`:

* ``lure.session_opened`` / ``lure.command_*`` / ``lure.fallback_served``
  / ``lure.session_closed`` (Stage 4.2) populate the Stage 4 session
  store.
* ``bridge.intent_extracted`` (Stage 7) persists the operator-facing
  intent summary keyed on session_id.

Every dispatched event additionally triggers a WebSocket fan-out via
the DashboardState facade so the SPA receives live updates.

Path "alpha" from the Stage 4.2 design discussion: zero new IPC,
zero new auth surface. The audit log is the wire format.

Lifecycle:

* Constructed at dashboard startup with the audit path, a
  :class:`DashboardState`, and a sidecar offset-cache path.
* :meth:`start` spawns the background task. Idempotent.
* :meth:`stop` cancels the task, persists the final offset,
  returns.
* One instance per dashboard process.

The tailer treats the audit log as a single producer (the lure
process) and itself as the sole consumer that mutates the
SessionStore. Multiple readers + one writer is SQLite's WAL happy
path; running two tailers against the same DB would produce
idempotent duplicates and is not supported.

Copytruncate is the only rotation strategy supported. If an
operator switches to rename-based rotation the tailer will keep
reading the rotated file until the next restart - the symptom is
"audit events stop showing up in the dashboard." Documented in
``docs/RUNBOOK.md`` Audit log rotation.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final
from uuid import UUID

from anglerfish.audit import AuditLog
from anglerfish.models.embedding import SessionEmbedding
from anglerfish.models.intent import IntentSummary
from anglerfish.models.persistence import PersistenceEvent
from anglerfish.models.session import CommandTurn, ResponseSource, SessionSnapshot

if TYPE_CHECKING:
    from anglerfish.dashboard.state import DashboardState

__all__ = ["AuditTailer"]


_logger = logging.getLogger(__name__)

# Locked during operator review (see Stage 4.2 design doc):
# 0.5s is the published default; stat() on a local file is cheap
# and sub-second freshness matches dashboard user expectations.
DEFAULT_POLL_INTERVAL_SECONDS: Final[float] = 0.5

# Backoff multiplier applied to the poll interval when the
# SessionStore reports unhealthy (three consecutive batch failures
# trip this; success resets it). 5x keeps the retry loud enough in
# logs to notice but quiet enough not to thrash.
_BACKOFF_MULTIPLIER: Final[float] = 5.0
_BACKOFF_FAILURE_THRESHOLD: Final[int] = 3

# Tailer schema version for the offset cache. Bump when the cache
# JSON shape changes (e.g. add a checksum field).
_CACHE_SCHEMA_VERSION: Final[int] = 1

# Per-decision in the design doc: placeholder fields when we
# auto-create a session row from a command event that arrived
# before its ``lure.session_opened``. The values are deliberately
# obvious so an operator who sees one in /api/sessions knows it's
# a placeholder and not real data.
_PLACEHOLDER_USERNAME: Final[str] = "unknown"
_PLACEHOLDER_HOSTNAME: Final[str] = "unknown"
_PLACEHOLDER_CWD: Final[str] = "/"


# Map audit event_type → CommandTurn.source. The existing
# ResponseSource enum (anglerfish.models.session) has no NATIVE
# variant; per its docstring, AI covers both LLM-driven and
# "deterministic in-bridge handling" (e.g. cd, blank input). The
# tailer respects that schema and folds native commands into AI.
# The audit log still distinguishes the two via event_type for
# operators who grep the log directly.
_COMMAND_EVENTS_TO_SOURCE = {
    "lure.command_native": ResponseSource.AI,
    "lure.command_bridge": ResponseSource.AI,
    "lure.fallback_served": ResponseSource.FALLBACK,
}


class AuditTailer:
    """Tail the audit JSONL and translate lure events to SessionStore writes."""

    def __init__(
        self,
        *,
        audit_path: Path,
        dashboard_state: DashboardState,
        offset_cache_path: Path,
        poll_interval_seconds: float = DEFAULT_POLL_INTERVAL_SECONDS,
        audit_log: AuditLog | None = None,
        cluster_similarity_threshold: float = 0.85,
        persona_bias_threshold: float = 0.92,
    ) -> None:
        if poll_interval_seconds <= 0:
            raise ValueError("poll_interval_seconds must be positive")
        if not 0.0 <= cluster_similarity_threshold <= 1.0:
            raise ValueError(
                "cluster_similarity_threshold must be in [0, 1]",
            )
        if not 0.0 <= persona_bias_threshold <= 1.0:
            raise ValueError(
                "persona_bias_threshold must be in [0, 1]",
            )
        self._audit_path = audit_path
        self._state = dashboard_state
        self._cache_path = offset_cache_path
        self._poll_interval = poll_interval_seconds
        # Stage 8: the tailer writes a bridge.cluster_match audit event
        # right after persisting an embedding when find_similar
        # returns one or more neighbours above the threshold. The
        # audit log handle is optional so existing test fixtures that
        # construct the tailer without it keep working; cluster_match
        # emission is silently skipped in that case.
        self._audit_log = audit_log
        self._cluster_threshold = cluster_similarity_threshold
        # Stage 9 slice 9.4: when a neighbour's similarity crosses the
        # persona-bias threshold AND its persona differs from the
        # just-closed session's, the tailer rewrites the closed
        # session's persona column so the selector's recurrence query
        # picks up the rebound on the next session-open. Default 0.92
        # is stricter than cluster_similarity_threshold (0.85) because
        # rebounding a future session's persona is stronger than
        # firing an alert.
        self._persona_bias_threshold = persona_bias_threshold
        self._stop_event = asyncio.Event()
        self._task: asyncio.Task[None] | None = None
        self._start_lock = asyncio.Lock()
        # In-memory per-session snapshots so we can build cumulative
        # `turns` tuples for DashboardState.update_session without a
        # store round-trip on every event.
        self._accumulators: dict[UUID, SessionSnapshot] = {}
        # Persisted byte offset into the audit file.
        self._offset: int = 0
        # Consecutive write-batch failures; trips backoff mode.
        self._consecutive_failures: int = 0

    @property
    def audit_path(self) -> Path:
        return self._audit_path

    @property
    def offset(self) -> int:
        return self._offset

    @property
    def is_running(self) -> bool:
        return self._task is not None and not self._task.done()

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        """Spawn the background poll task. Idempotent if already running."""
        async with self._start_lock:
            if self.is_running:
                return
            self._stop_event.clear()
            self._load_offset_cache()
            self._task = asyncio.create_task(
                self._run(),
                name="audit-tailer",
            )

    async def stop(self) -> None:
        """Request shutdown, drain pending work, persist final offset."""
        async with self._start_lock:
            task = self._task
            if task is None:
                return
            self._stop_event.set()
            try:
                await asyncio.wait_for(task, timeout=self._poll_interval * 4)
            except TimeoutError:
                task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await task
            self._task = None
            self._save_offset_cache()

    # ------------------------------------------------------------------
    # Polling loop
    # ------------------------------------------------------------------

    async def _run(self) -> None:
        while not self._stop_event.is_set():
            try:
                await self._poll_once()
            except Exception:
                _logger.exception("audit_tailer: unexpected error in poll cycle")
                self._consecutive_failures += 1
            interval = self._poll_interval
            if self._consecutive_failures >= _BACKOFF_FAILURE_THRESHOLD:
                interval = self._poll_interval * _BACKOFF_MULTIPLIER
            try:
                await asyncio.wait_for(self._stop_event.wait(), timeout=interval)
            except TimeoutError:
                continue

    async def _poll_once(self) -> None:
        """Read newly-appended audit lines and dispatch them."""
        if not self._audit_path.is_file():
            return
        try:
            stat = self._audit_path.stat()
        except OSError as exc:
            _logger.warning("audit_tailer: stat(%s) failed: %s", self._audit_path, exc)
            return

        if stat.st_size < self._offset:
            # Copytruncate detected: file size shrunk under our feet.
            # Reset to the start of the new generation. Previously-
            # processed lines in the old generation stay processed
            # because in-memory accumulators + store rows survive.
            _logger.info(
                "audit_tailer: rotation detected (size=%d < offset=%d); resetting offset",
                stat.st_size,
                self._offset,
            )
            self._offset = 0

        if stat.st_size == self._offset:
            return

        try:
            new_bytes = await asyncio.to_thread(self._read_from_offset, stat.st_size)
        except OSError as exc:
            _logger.warning("audit_tailer: read(%s) failed: %s", self._audit_path, exc)
            return

        # Split on newline; the last fragment may be a partial line
        # written between our stat() and read(). Hold it for the next
        # cycle by advancing the offset only up to the last newline.
        if not new_bytes:
            return
        last_newline = new_bytes.rfind(b"\n")
        if last_newline == -1:
            # No complete line yet; do not advance.
            return
        complete = new_bytes[: last_newline + 1]
        advance = len(complete)

        events = list(self._parse_lines(complete))
        try:
            for event in events:
                await self._dispatch_event(event)
        except Exception:
            _logger.exception("audit_tailer: dispatch failed; offset unchanged")
            self._consecutive_failures += 1
            return

        # Only advance the offset after the whole batch dispatched
        # successfully so a transient store failure replays cleanly.
        self._offset += advance
        self._consecutive_failures = 0
        self._save_offset_cache()

    def _read_from_offset(self, end: int) -> bytes:
        with self._audit_path.open("rb") as fp:
            fp.seek(self._offset)
            return fp.read(end - self._offset)

    @staticmethod
    def _parse_lines(blob: bytes) -> list[dict[str, Any]]:
        events: list[dict[str, Any]] = []
        for raw_line in blob.splitlines():
            line = raw_line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                _logger.warning("audit_tailer: skipping malformed line")
                continue
            if isinstance(event, dict):
                events.append(event)
        return events

    # ------------------------------------------------------------------
    # Event dispatch
    # ------------------------------------------------------------------

    async def _dispatch_event(self, event: dict[str, Any]) -> None:
        event_type = event.get("event_type")
        if not isinstance(event_type, str):
            return
        session_id_raw = event.get("session_id")
        if not isinstance(session_id_raw, str):
            # session_id is only on events we care about; everything
            # else (login_attempt, fingerprint, rate_limited, ...) is
            # threat-engine territory.
            return
        try:
            session_id = UUID(session_id_raw)
        except ValueError:
            _logger.warning(
                "audit_tailer: skipping event with non-UUID session_id=%r",
                session_id_raw,
            )
            return

        if event_type == "lure.session_opened":
            await self._handle_opened(session_id, event)
        elif event_type in _COMMAND_EVENTS_TO_SOURCE:
            await self._handle_command(
                session_id,
                event,
                _COMMAND_EVENTS_TO_SOURCE[event_type],
            )
        elif event_type == "lure.session_closed":
            await self._handle_closed(session_id, event)
        elif event_type == "bridge.intent_extracted":
            await self._handle_intent_extracted(session_id, event)
        elif event_type == "bridge.embedding_generated":
            await self._handle_embedding_generated(session_id, event)
        elif event_type == "bridge.persistence_attempt":
            await self._handle_persistence_attempt(session_id, event)
        # Everything else: silently ignored. Future stages add types
        # without churning the tailer.

    async def _handle_opened(self, session_id: UUID, event: dict[str, Any]) -> None:
        ts = _parse_ts(event) or _utcnow()
        source_ip = _str_field(event, "source_ip", default="unknown")
        username = _str_field(event, "username", default=_PLACEHOLDER_USERNAME)
        # If a command arrived first and we already auto-created an
        # accumulator, preserve its turns. The real open just upgrades
        # the metadata (source_ip / username come from this event).
        existing = self._accumulators.get(session_id)
        turns = existing.turns if existing is not None else ()
        snapshot = SessionSnapshot(
            session_id=session_id,
            source_ip=source_ip,
            username=username,
            fake_hostname=_PLACEHOLDER_HOSTNAME,
            fake_username=username,
            fake_cwd=_PLACEHOLDER_CWD,
            started_at=ts,
            last_activity_at=ts,
            turns=turns,
        )
        self._accumulators[session_id] = snapshot
        await self._state.update_session(snapshot)

    async def _handle_command(
        self,
        session_id: UUID,
        event: dict[str, Any],
        source: ResponseSource,
    ) -> None:
        ts = _parse_ts(event) or _utcnow()
        command = _str_field(event, "command", default="")
        if not command:
            return
        latency_raw = event.get("latency_ms")
        latency_ms = float(latency_raw) if isinstance(latency_raw, (int, float)) else 0.0

        turn = CommandTurn(
            command=command,
            response="",  # not in audit; design accepts this
            source=source,
            timestamp=ts,
            latency_ms=latency_ms,
        )
        snapshot = self._accumulators.get(session_id)
        if snapshot is None:
            # Command-before-open: synthesize a placeholder session
            # row from the command event. If a real session_opened
            # arrives later it will overwrite source_ip/username.
            source_ip = _str_field(event, "source_ip", default="unknown")
            snapshot = SessionSnapshot(
                session_id=session_id,
                source_ip=source_ip,
                username=_PLACEHOLDER_USERNAME,
                fake_hostname=_PLACEHOLDER_HOSTNAME,
                fake_username=_PLACEHOLDER_USERNAME,
                fake_cwd=_PLACEHOLDER_CWD,
                started_at=ts,
                last_activity_at=ts,
                turns=(),
            )
        snapshot = snapshot.model_copy(
            update={
                "last_activity_at": ts,
                "turns": (*snapshot.turns, turn),
            },
        )
        self._accumulators[session_id] = snapshot
        await self._state.update_session(snapshot)

    async def _handle_closed(self, session_id: UUID, event: dict[str, Any]) -> None:
        # end_session() reads the snapshot from the store and publishes
        # SESSION_ENDED with its payload; an unknown session_id is a
        # silent no-op (the store has no row). Drop our accumulator
        # either way so memory doesn't grow unboundedly with closed
        # sessions.
        del event  # unused; signature kept for symmetry
        self._accumulators.pop(session_id, None)
        await self._state.end_session(session_id)

    async def _handle_intent_extracted(
        self,
        session_id: UUID,
        event: dict[str, Any],
    ) -> None:
        """Persist a Stage 7 :class:`IntentSummary` event.

        The bridge audits the full payload; we reconstruct the
        :class:`IntentSummary` from the event fields and delegate to
        :meth:`DashboardState.upsert_intent`. Missing or
        type-mismatched fields skip the event silently (matches the
        existing tailer pattern - the log is best-effort, not
        load-bearing).
        """
        summary = _parse_intent_event(session_id, event)
        if summary is None:
            return
        await self._state.upsert_intent(summary)

    async def _handle_embedding_generated(
        self,
        session_id: UUID,
        event: dict[str, Any],
    ) -> None:
        """Persist a Stage 8 :class:`SessionEmbedding` + emit cluster_match
        + (Stage 9) check for cluster-bias persona rebound.

        After upserting, runs find_similar against the freshly
        persisted vector; if any neighbours cross the configured
        threshold, emits ``bridge.cluster_match`` via the optional
        audit-log handle. Cluster-match emission is skipped (silently)
        when no audit_log was wired into the tailer.

        Stage 9: when the top neighbour's similarity also crosses the
        persona_bias_threshold AND its persona differs from the just-
        closed session's persona, rewrite the just-closed session's
        persona column to the neighbour's and emit
        ``bridge.persona_rebound``. The selector's recurrence query
        picks up the rebound on the next session-open from this
        source IP.
        """
        embedding = _parse_embedding_event(session_id, event)
        if embedding is None:
            return
        await self._state.upsert_embedding(embedding)
        if self._audit_log is None:
            return
        neighbours = await self._state.find_similar(
            session_id,
            k=5,
            min_similarity=self._cluster_threshold,
        )
        if not neighbours:
            return
        self._audit_log.record(
            "bridge.cluster_match",
            session_id=str(session_id),
            model=embedding.model,
            threshold=self._cluster_threshold,
            matches=[
                {
                    "session_id": str(neighbour.session_id),
                    "similarity": round(similarity, 6),
                }
                for neighbour, similarity in neighbours
            ],
        )
        await self._maybe_rebound_persona(session_id, neighbours)

    async def _maybe_rebound_persona(
        self,
        session_id: UUID,
        neighbours: list[tuple[SessionEmbedding, float]],
    ) -> None:
        """Stage 9 cluster-bias rebound: rewrite persona if top match crosses bias.

        Pre-conditions guaranteed by caller: ``neighbours`` is non-
        empty and an audit_log handle is wired. The top neighbour is
        the highest-similarity entry (find_similar returns
        descending-by-similarity).
        """
        top_neighbour, top_similarity = neighbours[0]
        if top_similarity < self._persona_bias_threshold:
            return
        closed = await self._state.get_session(session_id)
        neighbour_row = await self._state.get_session(top_neighbour.session_id)
        if closed is None or neighbour_row is None:
            return
        new_persona = neighbour_row.persona_name
        old_persona = closed.persona_name
        if new_persona is None or new_persona == old_persona:
            return
        await self._state.update_session_persona(session_id, new_persona)
        assert self._audit_log is not None  # noqa: S101  # guarded by caller
        self._audit_log.record(
            "bridge.persona_rebound",
            session_id=str(session_id),
            source_ip=closed.source_ip,
            old_persona=old_persona,
            new_persona=new_persona,
            neighbour_session_id=str(top_neighbour.session_id),
            similarity=round(top_similarity, 6),
        )

    async def _handle_persistence_attempt(
        self,
        session_id: UUID,
        event: dict[str, Any],
    ) -> None:
        """Persist a Stage 10 ``bridge.persistence_attempt`` audit event.

        Parses the event into a :class:`PersistenceEvent` and
        forwards to :meth:`DashboardState.record_persistence_event`.
        Malformed events log a warning and skip (matches the
        existing intent + embedding parser patterns - one bad
        audit line never trips the tailer batch loop).

        Replay of an already-persisted line lands as an INSERT OR
        IGNORE at the SQL layer (the schema's UNIQUE constraint on
        source_ip + kind + sub_key + created_at). The handler does
        not distinguish a fresh insert from a deduped replay - the
        idempotent path is the same operator-visible outcome.
        """
        parsed = _parse_persistence_attempt_event(session_id, event)
        if parsed is None:
            return
        persistence_event, source_ip, created_at = parsed
        await self._state.record_persistence_event(
            persistence_event,
            source_ip=source_ip,
            session_id=session_id,
            created_at=created_at,
        )

    # ------------------------------------------------------------------
    # Offset cache
    # ------------------------------------------------------------------

    def _load_offset_cache(self) -> None:
        """Restore the byte offset from the sidecar file if present.

        Corrupt or schema-mismatched cache is treated as absent: the
        tailer starts from offset 0. SessionStore writes are
        idempotent on session_id + turn sequence, so re-processing
        the whole log is safe (just slow on a multi-GB log).
        """
        if not self._cache_path.is_file():
            self._offset = 0
            return
        try:
            raw = self._cache_path.read_text(encoding="utf-8")
            payload = json.loads(raw)
        except (OSError, json.JSONDecodeError) as exc:
            _logger.warning(
                "audit_tailer: offset cache %s unreadable (%s); starting from 0",
                self._cache_path,
                exc,
            )
            self._offset = 0
            return
        if not isinstance(payload, dict):
            self._offset = 0
            return
        if payload.get("schema_version") != _CACHE_SCHEMA_VERSION:
            self._offset = 0
            return
        if payload.get("audit_path") != str(self._audit_path):
            # Operator relocated the log; old offset is meaningless.
            self._offset = 0
            return
        offset = payload.get("offset")
        if isinstance(offset, int) and offset >= 0:
            self._offset = offset
        else:
            self._offset = 0

    def _save_offset_cache(self) -> None:
        """Atomically write the cache via temp-file + os.replace."""
        try:
            self._cache_path.parent.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            _logger.warning(
                "audit_tailer: cache dir %s mkdir failed: %s",
                self._cache_path.parent,
                exc,
            )
            return
        payload = {
            "schema_version": _CACHE_SCHEMA_VERSION,
            "audit_path": str(self._audit_path),
            "offset": self._offset,
            "last_persisted_at": _utcnow().isoformat(),
        }
        tmp_path = self._cache_path.with_suffix(self._cache_path.suffix + ".tmp")
        try:
            tmp_path.write_text(
                json.dumps(payload, separators=(",", ":")),
                encoding="utf-8",
            )
            os.replace(tmp_path, self._cache_path)
        except OSError as exc:
            _logger.warning(
                "audit_tailer: cache write to %s failed: %s",
                self._cache_path,
                exc,
            )
            with contextlib.suppress(OSError):
                tmp_path.unlink()


def _utcnow() -> datetime:
    return datetime.now(tz=UTC)


def _parse_ts(event: dict[str, Any]) -> datetime | None:
    raw = event.get("ts")
    if not isinstance(raw, str):
        return None
    try:
        return datetime.fromisoformat(raw)
    except ValueError:
        return None


def _str_field(event: dict[str, Any], key: str, *, default: str) -> str:
    value = event.get(key)
    return value if isinstance(value, str) and value else default


_VALID_ACTOR_PROFILES = frozenset({"opportunistic", "automated", "targeted", "exploratory"})
_VALID_CONFIDENCES = frozenset({"low", "medium", "high"})


def _parse_intent_event(
    session_id: UUID,
    event: dict[str, Any],
) -> IntentSummary | None:
    """Reconstruct an :class:`IntentSummary` from a bridge.intent_extracted event.

    Returns :data:`None` (with a warning log) when any required
    field is missing or type-mismatched. The audit log is best-
    effort context for the tailer; a malformed record never
    crashes the tailer.
    """
    actor_profile = event.get("actor_profile")
    confidence = event.get("confidence")
    intent = event.get("intent")
    why = event.get("why")
    summary = event.get("summary")
    extracted_at_raw = event.get("extracted_at")
    if (
        actor_profile not in _VALID_ACTOR_PROFILES
        or confidence not in _VALID_CONFIDENCES
        or not isinstance(intent, str)
        or not isinstance(why, str)
        or not isinstance(summary, str)
        or not isinstance(extracted_at_raw, str)
    ):
        _logger.warning(
            "audit_tailer: bridge.intent_extracted event missing or "
            "malformed required fields for session_id=%s",
            session_id,
        )
        return None
    techniques_raw = event.get("matched_techniques", [])
    if not isinstance(techniques_raw, list):
        techniques_raw = []
    techniques = tuple(t for t in techniques_raw if isinstance(t, str))
    try:
        extracted_at = datetime.fromisoformat(extracted_at_raw)
    except ValueError:
        _logger.warning(
            "audit_tailer: bridge.intent_extracted has malformed extracted_at=%r for session_id=%s",
            extracted_at_raw,
            session_id,
        )
        return None
    try:
        return IntentSummary(
            session_id=session_id,
            actor_profile=actor_profile,
            intent=intent,
            why=why,
            matched_techniques=techniques,
            confidence=confidence,
            summary=summary,
            extracted_at=extracted_at,
        )
    except ValueError as exc:
        # Pydantic validation (string-length caps, etc.) - the
        # bridge produced a record the schema rejects. Audit-side
        # data corruption; log + drop.
        _logger.warning(
            "audit_tailer: bridge.intent_extracted failed schema validation for session_id=%s: %s",
            session_id,
            exc,
        )
        return None


def _parse_embedding_event(
    session_id: UUID,
    event: dict[str, Any],
) -> SessionEmbedding | None:
    """Reconstruct a :class:`SessionEmbedding` from a bridge.embedding_generated event.

    Mirrors :func:`_parse_intent_event`: missing or type-mismatched
    fields produce a warning and a None return so the tailer skips
    the event without crashing. The bridge serialises ``vector``
    as a JSON list of floats; we coerce it back into the immutable
    tuple shape :class:`SessionEmbedding` expects.
    """
    vector_raw = event.get("vector")
    dimension = event.get("dimension")
    model = event.get("model")
    generated_at_raw = event.get("generated_at")
    if (
        not isinstance(vector_raw, list)
        or not isinstance(dimension, int)
        or not isinstance(model, str)
        or not isinstance(generated_at_raw, str)
    ):
        _logger.warning(
            "audit_tailer: bridge.embedding_generated event missing or "
            "malformed required fields for session_id=%s",
            session_id,
        )
        return None
    if not all(isinstance(v, (int, float)) for v in vector_raw):
        _logger.warning(
            "audit_tailer: bridge.embedding_generated vector for session_id=%s "
            "contains non-numeric entries; dropping",
            session_id,
        )
        return None
    try:
        generated_at = datetime.fromisoformat(generated_at_raw)
    except ValueError:
        _logger.warning(
            "audit_tailer: bridge.embedding_generated has malformed "
            "generated_at=%r for session_id=%s",
            generated_at_raw,
            session_id,
        )
        return None
    try:
        return SessionEmbedding(
            session_id=session_id,
            vector=tuple(float(v) for v in vector_raw),
            dimension=dimension,
            model=model,
            generated_at=generated_at,
        )
    except ValueError as exc:
        # Pydantic min/max-length on vector + dimension cross-check
        # land here. Treat as audit-side corruption; log + drop.
        _logger.warning(
            "audit_tailer: bridge.embedding_generated failed schema "
            "validation for session_id=%s: %s",
            session_id,
            exc,
        )
        return None


_VALID_PERSISTENCE_KINDS = frozenset({"crontab", "systemctl", "authorized_keys"})
_VALID_PERSISTENCE_SOURCES = frozenset({"regex", "llm"})


def _parse_persistence_attempt_event(
    session_id: UUID,
    event: dict[str, Any],
) -> tuple[PersistenceEvent, str, datetime] | None:
    """Reconstruct a :class:`PersistenceEvent` + source_ip + created_at.

    Returns a 3-tuple ``(event, source_ip, created_at)`` on
    success or :data:`None` (with a warning log) when any
    required field is missing / malformed. Mirrors the intent +
    embedding parser patterns so a corrupt audit line never
    crashes the tailer batch loop.

    ``created_at`` is read from the event's own ``created_at``
    field (set by the bridge classifier on emit), not from the
    audit-record ``ts``. Using a dedicated field keeps the
    replay-dedup contract honest: the UNIQUE schema constraint
    is on (source_ip, kind, sub_key, created_at) and operators
    who hand-edit / replay audit lines control created_at
    directly.
    """
    kind = event.get("kind")
    source_ip = event.get("source_ip")
    payload = event.get("payload")
    source = event.get("source")
    created_at_raw = event.get("created_at")
    if (
        kind not in _VALID_PERSISTENCE_KINDS
        or source not in _VALID_PERSISTENCE_SOURCES
        or not isinstance(source_ip, str)
        or not source_ip
        or not isinstance(payload, str)
        or not payload
        or not isinstance(created_at_raw, str)
    ):
        _logger.warning(
            "audit_tailer: bridge.persistence_attempt event missing or "
            "malformed required fields for session_id=%s",
            session_id,
        )
        return None
    sub_key = event.get("sub_key")
    if sub_key is not None and not isinstance(sub_key, str):
        _logger.warning(
            "audit_tailer: bridge.persistence_attempt sub_key has wrong type "
            "for session_id=%s; dropping",
            session_id,
        )
        return None
    try:
        created_at = datetime.fromisoformat(created_at_raw)
    except ValueError:
        _logger.warning(
            "audit_tailer: bridge.persistence_attempt has malformed "
            "created_at=%r for session_id=%s",
            created_at_raw,
            session_id,
        )
        return None
    try:
        persistence_event = PersistenceEvent(
            kind=kind,
            sub_key=sub_key,
            payload=payload,
            source=source,
        )
    except ValueError as exc:
        _logger.warning(
            "audit_tailer: bridge.persistence_attempt failed schema "
            "validation for session_id=%s: %s",
            session_id,
            exc,
        )
        return None
    return persistence_event, source_ip, created_at
