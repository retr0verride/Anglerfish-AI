"""Tor exit-node detection.

:class:`TorExitList` reads a newline-delimited list of Tor exit-node IP
addresses from disk and caches it in memory. The file is reloaded when
it has been modified since the last load **or** when the configured
refresh interval has elapsed — whichever happens first. This makes the
component robust both to operators dropping in a freshly downloaded
list (mtime changes) and to operators who forget (interval triggers
the periodic re-check).

The file format is one IP per line; blank lines and lines starting with
``#`` are ignored. Invalid lines are silently skipped (the file is
attacker-adjacent — we never let it crash the honeypot).
"""

from __future__ import annotations

import asyncio
import ipaddress
import time
from collections.abc import Callable
from pathlib import Path

__all__ = ["TorExitList"]


_Clock = Callable[[], float]


class TorExitList:
    """Async-safe Tor exit IP set with mtime-aware refresh."""

    def __init__(
        self,
        path: Path,
        *,
        refresh_interval_s: float,
        clock: _Clock | None = None,
    ) -> None:
        if refresh_interval_s <= 0:
            raise ValueError(
                f"refresh_interval_s must be positive, got {refresh_interval_s}",
            )
        self._path = path
        self._refresh_interval_s = refresh_interval_s
        self._clock: _Clock = clock if clock is not None else time.monotonic
        self._lock = asyncio.Lock()
        self._exits: frozenset[str] = frozenset()
        self._loaded_at: float | None = None
        self._mtime: float | None = None

    @property
    def path(self) -> Path:
        return self._path

    @property
    def refresh_interval_s(self) -> float:
        return self._refresh_interval_s

    async def contains(self, ip: str) -> bool:
        """Return True if ``ip`` is currently listed as a Tor exit."""
        await self._maybe_refresh()
        normalised = self._normalise_ip(ip)
        if normalised is None:
            return False
        return normalised in self._exits

    async def reload(self) -> None:
        """Force a reload from disk."""
        async with self._lock:
            self._reload_locked()

    async def size(self) -> int:
        await self._maybe_refresh()
        return len(self._exits)

    async def _maybe_refresh(self) -> None:
        now = self._clock()
        if self._loaded_at is None:
            async with self._lock:
                if self._loaded_at is None:
                    self._reload_locked()
            return

        elapsed = now - self._loaded_at
        interval_due = elapsed >= self._refresh_interval_s
        mtime_changed = await asyncio.to_thread(self._mtime_changed)
        if not (interval_due or mtime_changed):
            return
        async with self._lock:
            self._reload_locked()

    def _mtime_changed(self) -> bool:
        try:
            current_mtime = self._path.stat().st_mtime
        except FileNotFoundError:
            return self._mtime is not None
        return current_mtime != self._mtime

    def _reload_locked(self) -> None:
        exits: set[str] = set()
        try:
            current_mtime: float | None = self._path.stat().st_mtime
            content = self._path.read_text(encoding="utf-8", errors="replace")
        except FileNotFoundError:
            current_mtime = None
            content = ""
        for line in content.splitlines():
            ip = line.strip()
            if not ip or ip.startswith("#"):
                continue
            normalised = self._normalise_ip(ip)
            if normalised is not None:
                exits.add(normalised)
        self._exits = frozenset(exits)
        self._mtime = current_mtime
        self._loaded_at = self._clock()

    @staticmethod
    def _normalise_ip(ip: str) -> str | None:
        try:
            return str(ipaddress.ip_address(ip.strip()))
        except ValueError:
            return None
