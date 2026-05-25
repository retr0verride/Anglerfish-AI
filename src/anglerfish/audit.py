"""Append-only audit log for security-relevant events.

A separate stream from the session-capture and threat-event paths:
operators want to be able to ask "what did the operators do?" without
the answer being drowned out by captured-attacker noise. The log is
JSONL — one event per line, ``fsync``\\ ed after each write — and is
deliberately *append-only* in the sense that the writer never seeks
or rewrites earlier records.

The first-boot systemd unit sets ``chattr +a`` on the file on
supported filesystems (ext2/3/4, btrfs, xfs), upgrading the
convention to a filesystem-level invariant: even root can't truncate
or rewrite past records without first removing the attribute. The
file can still be deleted by root; pair with off-host shipping
(syslog forwarder, backup job, your SIEM of choice) for true
tamper-evidence.

Events recorded today (dot-namespaced: ``<subsystem>.<verb>_<noun>``):

* Wizard: ``wizard.run``, ``wizard.secrets_regenerated``.
* Credentials: ``credentials.key_rotated``.
* Dashboard: ``dashboard.login_success``, ``dashboard.login_failure``,
  ``login_rate_limited``, ``dashboard.export_served``.
* Bridge: ``bridge.defense_fired``, ``bridge.defense_scan_truncated``,
  ``bridge.model_integrity_verified``, ``bridge.model_integrity_failed``,
  ``bridge.model_integrity_skipped``, ``bridge.budget_exhausted``,
  ``bridge.overrides_read_failed``, ``bridge.wasting_applied``.
* Dashboard (Stage 6): ``dashboard.overrides_published``,
  ``dashboard.overrides_publish_failed``.
* Lure: ``lure.server_started``, ``lure.server_stopped``,
  ``lure.session_opened``, ``lure.session_closed``,
  ``lure.command_native``, ``lure.command_bridge``,
  ``lure.fallback_served``, ``lure.bridge_unavailable``,
  ``lure.rate_limited``, ``lure.subsystem_refused``,
  ``lure.fingerprint_observed``, ``lure.login_attempt``.
* Threat: ``threat.alert_fired``.
* Geo: ``geo.update_succeeded``, ``geo.update_failed``.
* LLM: ``llm.warmup_succeeded``, ``llm.warmup_failed``.

The Stage 4.2 audit-log tailer in
:mod:`anglerfish.dashboard.audit_tailer` consumes the per-session
``lure.*`` events to populate the persistent session store.

The log is best-effort: a write failure logs a warning but never raises.
The audit log MUST NOT itself crash the application — losing it would
be bad, but crashing because we couldn't write it would be worse.
"""

from __future__ import annotations

import json
import logging
import os
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Self

__all__ = ["DEFAULT_AUDIT_PATH", "AuditLog"]


DEFAULT_AUDIT_PATH = Path("/var/log/anglerfish/audit.jsonl")

_logger = logging.getLogger(__name__)


class AuditLog:
    """Process-singleton-ready append-only JSONL audit logger.

    Thread-safe via a re-entrant lock; safe to call from asyncio tasks
    because the disk write happens under the lock and is short.
    """

    def __init__(self, path: Path | None = None) -> None:
        self._path = path if path is not None else DEFAULT_AUDIT_PATH
        self._lock = threading.RLock()

    @property
    def path(self) -> Path:
        return self._path

    def record(self, event_type: str, **fields: Any) -> None:
        """Append one event. Never raises — write failures are logged."""
        if not event_type:
            raise ValueError("event_type cannot be empty")
        record: dict[str, Any] = {
            "ts": datetime.now(tz=UTC).isoformat(),
            "event_type": event_type,
        }
        record.update(fields)

        try:
            payload = json.dumps(record, default=str, separators=(",", ":"))
        except (TypeError, ValueError) as exc:
            _logger.warning(
                "audit.record: payload not JSON-serialisable: %s field-keys=%s",
                exc,
                sorted(fields),
            )
            return

        line = (payload + "\n").encode("utf-8")
        with self._lock:
            try:
                self._path.parent.mkdir(parents=True, exist_ok=True)
                with self._path.open("ab") as fp:
                    fp.write(line)
                    fp.flush()
                    os.fsync(fp.fileno())
            except OSError as exc:
                _logger.warning(
                    "audit.record: write to %s failed: %s",
                    self._path,
                    exc,
                )

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_exc: object) -> None:
        # No persistent file handle to close — each write is atomic.
        return
