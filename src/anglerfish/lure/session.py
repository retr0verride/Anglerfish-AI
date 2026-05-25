"""Per-attacker session state held by the lure process.

Mirrors the shape of :class:`anglerfish.bridge.session.SessionContext`
but lives in the lure process. The bridge keeps its own
``SessionContext`` for the LLM-facing history window; the lure keeps
this one for shell-state that does not need to round-trip to the
bridge on every command (cwd, command history, source IP, etc.).

The two contexts are correlated by the same UUID: the lure opens a
bridge session via HTTP, receives the UUID, and uses it as the local
session key.
"""

from __future__ import annotations

from collections import deque
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import UUID

from anglerfish.bridge.path import normalise_path

__all__ = ["LureCommandRecord", "LureSessionContext"]


@dataclass(frozen=True)
class LureCommandRecord:
    """One entry in the lure-side command history.

    Stored in-process, not persisted: Stage 3 (persistent session
    store) will subsume this. For Stage 2 it is enough that the
    ``history`` builtin can render past commands and the audit log
    has access to them on session close.
    """

    command: str
    response_source: str  # "native" | "bridge" | "fallback"
    when: datetime


class LureSessionContext:
    """Mutable shell state for one attacker connection.

    Not frozen: ``cwd`` and ``history`` mutate over the session
    lifetime. The class is the lure's analogue of
    ``bridge.SessionContext`` but holds shell-only state, no LLM
    history (the bridge keeps that on its side).
    """

    def __init__(
        self,
        session_id: UUID,
        *,
        source_ip: str,
        username: str,
        hostname: str,
        cwd: str,
        history_window: int = 200,
    ) -> None:
        if history_window < 1:
            raise ValueError(f"history_window must be >= 1, got {history_window}")
        self._session_id = session_id
        self._source_ip = source_ip
        self._username = username
        self._hostname = hostname
        self._cwd = normalise_path(cwd)
        self._history: deque[LureCommandRecord] = deque(maxlen=history_window)
        self._opened_at = datetime.now(tz=UTC)

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
    def hostname(self) -> str:
        return self._hostname

    @property
    def cwd(self) -> str:
        return self._cwd

    @property
    def opened_at(self) -> datetime:
        return self._opened_at

    def update_cwd(self, new_cwd: str) -> None:
        """Normalise ``new_cwd`` and store it as the session's current directory."""
        self._cwd = normalise_path(new_cwd)

    def record(self, command: str, *, response_source: str) -> None:
        """Append ``command`` to the session history with the current timestamp.

        ``response_source`` is the literal ``"native"`` / ``"bridge"`` /
        ``"fallback"`` tag describing which handler produced the response.
        """
        self._history.append(
            LureCommandRecord(
                command=command,
                response_source=response_source,
                when=datetime.now(tz=UTC),
            ),
        )

    def history(self) -> Iterable[LureCommandRecord]:
        """Return the recorded history (oldest first)."""
        return tuple(self._history)

    def command_count(self) -> int:
        """Return the number of commands recorded in the session history."""
        return len(self._history)
