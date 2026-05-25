"""Dashboard-side writer for the runtime overrides JSON.

Pairs with :class:`anglerfish.bridge.overrides_reader.BridgeOverridesReader`
on the bridge side. The dashboard calls :meth:`publish` after every
successful POST to ``/api/settings/bridge`` or
``/api/settings/features``; the bridge picks up the new value on
its next per-request poll (bounded by its cache TTL).

Writes are atomic: payload goes to a sibling tempfile in the same
directory, then :func:`os.replace` swaps it into place. Mode is
0640 on the final file so root-owned readers (the bridge) can see
it without permitting other users on the box.

Startup validation: :meth:`ensure_writable` checks the parent
directory exists and is writable; the dashboard app factory calls
it before binding so a misconfigured publish path surfaces as a
clean startup failure rather than the first POST 500.
"""

from __future__ import annotations

import contextlib
import json
import logging
import os
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING, Any

from anglerfish.audit import AuditLog

if TYPE_CHECKING:
    from anglerfish.dashboard.overrides import RuntimeOverrides

__all__ = ["RuntimeOverridesPublisher"]


_FILE_MODE = 0o640


class RuntimeOverridesPublisher:
    """Atomically writes the dashboard's overrides snapshot to disk."""

    def __init__(
        self,
        path: Path,
        *,
        audit_log: AuditLog | None = None,
        logger: logging.Logger | None = None,
    ) -> None:
        self._path = path
        self._audit_log = audit_log
        self._logger = logger if logger is not None else logging.getLogger(__name__)

    @property
    def path(self) -> Path:
        return self._path

    def ensure_writable(self) -> None:
        """Confirm the parent directory exists and is writable.

        Called from the dashboard's app factory at startup so a
        misconfigured publish path fails fast. Creates the parent
        directory if missing (mkdir parents=True, mode 0750) so
        operators do not have to pre-stage /run/anglerfish/.
        """
        parent = self._path.parent
        if not parent.exists():
            parent.mkdir(parents=True, exist_ok=True, mode=0o750)
        if not os.access(parent, os.W_OK):
            raise PermissionError(
                f"overrides publish dir {parent} is not writable; "
                "fix permissions or set dashboard.overrides_publish_path "
                "to a writable location",
            )

    def publish(self, overrides: RuntimeOverrides, *, quiet: bool = False) -> None:
        """Write ``overrides.snapshot()`` to the publish path atomically.

        Best-effort: any OSError is logged + audited but never raised.
        The dashboard endpoint already returns 200 on the override
        change; surfacing a publish failure as a 500 would be a
        regression and not actionable from the operator's HTTP client.

        ``quiet=True`` skips the success audit event. Used for the
        startup synchronization publish where no operator action
        triggered the write; without quiet, the audit log would
        gain a ``dashboard.overrides_published`` event on every
        dashboard restart, polluting export windows.
        """
        snapshot = overrides.snapshot()
        try:
            self._write_atomic(snapshot)
        except OSError as exc:
            self._logger.warning(
                "dashboard.overrides_publish_failed path=%s error=%s",
                self._path,
                exc,
            )
            if self._audit_log is not None:
                self._audit_log.record(
                    "dashboard.overrides_publish_failed",
                    path=str(self._path),
                    error=f"{type(exc).__name__}: {exc}",
                )
            return
        if not quiet and self._audit_log is not None:
            self._audit_log.record(
                "dashboard.overrides_published",
                path=str(self._path),
                bridge_snapshot=snapshot.get("bridge", {}),
            )

    def _write_atomic(self, payload: dict[str, Any]) -> None:
        serialised = json.dumps(payload, indent=2, sort_keys=True) + "\n"
        parent = self._path.parent
        parent.mkdir(parents=True, exist_ok=True, mode=0o750)
        # NamedTemporaryFile leaves the file in place when delete=False
        # is set so we can rename it; tempfile.mkstemp would also work
        # but returns an fd we would have to wrap manually.
        fd, tmp_path_str = tempfile.mkstemp(
            prefix=self._path.name + ".",
            suffix=".tmp",
            dir=str(parent),
        )
        tmp_path = Path(tmp_path_str)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fp:
                fp.write(serialised)
                fp.flush()
                os.fsync(fp.fileno())
            with contextlib.suppress(OSError):
                os.chmod(tmp_path, _FILE_MODE)
            os.replace(tmp_path, self._path)
        except OSError:
            with contextlib.suppress(OSError):
                tmp_path.unlink()
            raise
