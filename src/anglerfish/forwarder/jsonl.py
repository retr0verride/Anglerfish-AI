"""Append-only JSONL sink used as the local fallback when HEC is unreachable.

Design choices, in order of importance:

* **Atomic per-record durability.** Each :meth:`JsonlSink.write` opens
  the target file, appends one JSON line, ``fsync``\\ s the file
  descriptor, and closes it. The cost of the open/fsync/close cycle is
  acceptable at honeypot event rates (single-digit events per second
  in the worst attack burst), and the result is that a crashed process
  never loses an acknowledged write.
* **Size-based rotation.** When the file exceeds ``max_size_bytes``,
  it is renamed to ``<path>.1`` (or ``.2``, ``.3``, etc. — whichever
  numbered slot is free) before the next write. Rotation never
  overwrites an existing rotated file.
* **No background threads.** All file work happens on the thread pool
  via :func:`asyncio.to_thread`, so the sink is safe to use from an
  asyncio task without manual locking around the OS-level file API —
  the per-instance lock serialises writers within a single process.
"""

from __future__ import annotations

import asyncio
import json
import os
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from anglerfish.forwarder.errors import JsonlWriteError

__all__ = ["JsonlSink"]


class JsonlSink:
    """Append-only JSONL writer with size-based rotation."""

    def __init__(
        self,
        path: Path,
        *,
        max_size_bytes: int = 100 * 1024 * 1024,
    ) -> None:
        if max_size_bytes <= 0:
            raise ValueError(
                f"max_size_bytes must be positive, got {max_size_bytes}",
            )
        self._path = path
        self._max_size_bytes = max_size_bytes
        self._lock = asyncio.Lock()

    @property
    def path(self) -> Path:
        return self._path

    @property
    def max_size_bytes(self) -> int:
        return self._max_size_bytes

    async def write(self, record: Mapping[str, Any]) -> None:
        """Append one JSON record (one line). Raises :class:`JsonlWriteError`."""
        try:
            payload = json.dumps(record, default=str, separators=(",", ":"))
        except (TypeError, ValueError) as exc:
            raise JsonlWriteError(f"record is not JSON-serialisable: {exc}") from exc

        line = (payload + "\n").encode("utf-8")
        async with self._lock:
            try:
                await asyncio.to_thread(self._append_and_maybe_rotate, line)
            except OSError as exc:
                raise JsonlWriteError(
                    f"could not write to {self._path}: {exc}",
                ) from exc

    def _append_and_maybe_rotate(self, line: bytes) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        try:
            current_size = self._path.stat().st_size
        except FileNotFoundError:
            current_size = 0
        if current_size > 0 and current_size + len(line) > self._max_size_bytes:
            self._rotate()
        with self._path.open("ab") as fp:
            fp.write(line)
            fp.flush()
            os.fsync(fp.fileno())

    def _rotate(self) -> None:
        idx = 1
        while True:
            candidate = self._path.with_name(self._path.name + f".{idx}")
            if not candidate.exists():
                self._path.rename(candidate)
                return
            idx += 1
