"""Per-attacker shell session state.

A :class:`SessionContext` tracks everything the bridge needs to keep
the fake shell coherent across multiple commands: the working directory
the shell believes it is in, the bounded rolling history of recent
command/response turns, and the session's start / last-activity
timestamps.

Instances are **not** thread-safe; the bridge service uses them from a
single asyncio task per session, which is sufficient given the lure
serialises commands per attacker SSH channel.
"""

from __future__ import annotations

from collections import deque
from collections.abc import Callable
from datetime import UTC, datetime
from uuid import UUID

from anglerfish.models.session import CommandTurn, ResponseSource, SessionSnapshot

__all__ = ["SessionContext"]


_UtcNow = Callable[[], datetime]


def _default_utcnow() -> datetime:
    return datetime.now(tz=UTC)


class SessionContext:
    """Mutable per-attacker shell state."""

    __slots__ = (
        "_clock",
        "_command_count",
        "_cwd",
        "_fake_hostname",
        "_fake_username",
        "_history",
        "_last_activity_at",
        "_session_id",
        "_source_ip",
        "_started_at",
        "_username",
    )

    def __init__(
        self,
        session_id: UUID,
        *,
        source_ip: str,
        username: str,
        fake_hostname: str,
        fake_username: str,
        fake_cwd: str,
        history_window: int,
        clock: _UtcNow | None = None,
    ) -> None:
        if history_window < 0:
            raise ValueError(
                f"history_window must be non-negative, got {history_window}",
            )
        if not fake_cwd.startswith("/"):
            raise ValueError(f"fake_cwd must be absolute, got {fake_cwd!r}")
        self._clock: _UtcNow = clock if clock is not None else _default_utcnow
        self._session_id = session_id
        self._source_ip = source_ip
        self._username = username
        self._fake_hostname = fake_hostname
        self._fake_username = fake_username
        self._cwd = fake_cwd
        self._history: deque[CommandTurn] = deque(maxlen=history_window)
        # Stage 6: monotonic per-session command counter, distinct from
        # the windowed history length (which caps at history_window).
        # Used by wasting strategies to seed deterministic per-command
        # randomness without colliding when an attacker repeats a
        # command verbatim.
        self._command_count = 0
        now = self._clock()
        self._started_at = now
        self._last_activity_at = now

    @property
    def session_id(self) -> UUID:
        return self._session_id

    @property
    def source_ip(self) -> str:
        return self._source_ip

    @property
    def username(self) -> str:
        return self._username

    @property
    def fake_hostname(self) -> str:
        return self._fake_hostname

    @property
    def fake_username(self) -> str:
        return self._fake_username

    @property
    def cwd(self) -> str:
        return self._cwd

    @property
    def started_at(self) -> datetime:
        return self._started_at

    @property
    def last_activity_at(self) -> datetime:
        return self._last_activity_at

    @property
    def command_count(self) -> int:
        """Total commands recorded against this session (uncapped)."""
        return self._command_count

    def history(self) -> tuple[CommandTurn, ...]:
        """Return the recent command/response history (oldest first)."""
        return tuple(self._history)

    def record(
        self,
        command: str,
        response: str,
        *,
        source: ResponseSource,
        latency_ms: float,
    ) -> None:
        """Append a turn to the session's history and bump activity time."""
        timestamp = self._clock()
        self._history.append(
            CommandTurn(
                command=command,
                response=response,
                source=source,
                timestamp=timestamp,
                latency_ms=latency_ms,
            ),
        )
        self._command_count += 1
        self._last_activity_at = timestamp

    def update_cwd(self, new_cwd: str) -> None:
        """Move the fake shell to a new absolute working directory."""
        if not new_cwd.startswith("/"):
            raise ValueError(f"cwd must be absolute, got {new_cwd!r}")
        self._cwd = new_cwd

    def snapshot(self) -> SessionSnapshot:
        """Return an immutable view suitable for forwarding."""
        return SessionSnapshot(
            session_id=self._session_id,
            source_ip=self._source_ip,
            username=self._username,
            fake_hostname=self._fake_hostname,
            fake_username=self._fake_username,
            fake_cwd=self._cwd,
            started_at=self._started_at,
            last_activity_at=self._last_activity_at,
            turns=tuple(self._history),
        )
