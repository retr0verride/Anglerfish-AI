"""Bridge-side reader for dashboard-published runtime overrides.

Stage 3 shipped :class:`anglerfish.dashboard.overrides.RuntimeOverrides`
as a dashboard-in-process state object; the bridge had no way to
read it. Stage 6 closes that gap via a tmpfs JSON file: the
dashboard atomically writes the snapshot whenever an operator
flips a setting, the bridge polls the same path lazily per
request.

The poll is mtime-aware and TTL-cached:

* On each :meth:`current_wasting_strategy` call, if the cached
  value is younger than ``cache_ttl_s``, return it directly.
* After the TTL, stat the file; if mtime unchanged, just bump the
  cache timestamp; if changed (or missing-to-present), re-read and
  re-cache.
* A missing file is the common steady-state (operator never
  visited the dashboard); not an error. Falls back to the static
  value the constructor was given.
* A malformed or schema-mismatched file logs a warning, fires the
  ``bridge.overrides_read_failed`` audit event, and falls back to
  the static value.

The reader is intentionally synchronous: the polled file lives on
tmpfs (small, single-digit-ms read at worst), and threading async
through every command-handler caller for ~0.1 ms gain costs more
than it saves.
"""

from __future__ import annotations

import json
import logging
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from anglerfish.audit import AuditLog

__all__ = ["BridgeOverridesReader"]


_VALID_STRATEGIES = frozenset({"off", "light", "aggressive"})

_Clock = Callable[[], float]


class BridgeOverridesReader:
    """Lazy poller for the dashboard-published runtime overrides JSON."""

    def __init__(
        self,
        path: Path,
        *,
        cache_ttl_s: float,
        static_fallback: str,
        audit_log: AuditLog | None = None,
        logger: logging.Logger | None = None,
        clock: _Clock | None = None,
    ) -> None:
        if cache_ttl_s <= 0:
            raise ValueError(
                f"cache_ttl_s must be positive, got {cache_ttl_s}",
            )
        if static_fallback not in _VALID_STRATEGIES:
            raise ValueError(
                f"static_fallback must be one of {sorted(_VALID_STRATEGIES)}, "
                f"got {static_fallback!r}",
            )
        self._path = path
        self._cache_ttl_s = cache_ttl_s
        self._static_fallback = static_fallback
        self._audit_log = audit_log
        self._logger = logger if logger is not None else logging.getLogger(__name__)
        self._clock: _Clock = clock if clock is not None else time.monotonic
        self._cached_strategy: str = static_fallback
        self._cached_at: float | None = None
        self._cached_mtime: float | None = None

    @property
    def path(self) -> Path:
        return self._path

    @property
    def static_fallback(self) -> str:
        return self._static_fallback

    def current_wasting_strategy(self) -> str:
        """Return the operator's selected strategy, or the static fallback."""
        self._maybe_refresh()
        return self._cached_strategy

    def _maybe_refresh(self) -> None:
        now = self._clock()
        if self._cached_at is not None and (now - self._cached_at) < self._cache_ttl_s:
            return

        try:
            current_mtime: float | None = self._path.stat().st_mtime
        except FileNotFoundError:
            current_mtime = None

        if current_mtime == self._cached_mtime and self._cached_at is not None:
            # File unchanged since last read; refresh just the cache window.
            self._cached_at = now
            return

        # Either first read, file removed since last read, or mtime advanced.
        new_strategy = self._read_strategy()
        self._cached_strategy = new_strategy
        self._cached_mtime = current_mtime
        self._cached_at = now

    def _read_strategy(self) -> str:
        try:
            raw = self._path.read_text(encoding="utf-8")
        except FileNotFoundError:
            return self._static_fallback
        except OSError as exc:
            self._report_failure(f"read failed: {type(exc).__name__}: {exc}")
            return self._static_fallback

        try:
            payload: Any = json.loads(raw)
        except json.JSONDecodeError as exc:
            self._report_failure(f"malformed JSON: {exc}")
            return self._static_fallback

        if not isinstance(payload, dict):
            self._report_failure(
                f"top-level payload is not a JSON object: {type(payload).__name__}",
            )
            return self._static_fallback

        bridge_section = payload.get("bridge")
        if not isinstance(bridge_section, dict):
            self._report_failure("payload missing 'bridge' object")
            return self._static_fallback

        strategy = bridge_section.get("wasting_strategy")
        if not isinstance(strategy, str) or strategy not in _VALID_STRATEGIES:
            self._report_failure(
                f"bridge.wasting_strategy missing or invalid: {strategy!r}",
            )
            return self._static_fallback

        return strategy

    def _report_failure(self, reason: str) -> None:
        self._logger.warning(
            "bridge.overrides_read_failed path=%s reason=%s",
            self._path,
            reason,
        )
        if self._audit_log is not None:
            self._audit_log.record(
                "bridge.overrides_read_failed",
                path=str(self._path),
                error=reason,
            )
