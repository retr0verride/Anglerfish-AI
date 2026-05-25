"""FastAPI + WebSocket dashboard.

Public surface:

* :func:`create_app` — FastAPI app factory.
* :class:`DashboardState` — facade over :class:`SessionStore` plus
  an in-process WebSocket pub/sub. ``update_session`` /
  ``record_threat`` / ``end_session`` write through to the store
  and publish to subscribers. The pub/sub is ephemeral; the
  WebSocket endpoint consumes via :meth:`DashboardState.subscribe`.

  Stage 4.2 wired :class:`AuditTailer` as the production writer:
  the dashboard process tails ``/var/log/anglerfish/audit.jsonl``
  in the background, translates lure session events into
  ``update_session`` / ``record_turn`` / ``end_session`` calls,
  and the existing pub/sub fans them out to WebSocket subscribers.
  See ``docs/design/STAGE_4_2_audit_tailer.md``.
* :class:`DashboardEvent`, :class:`DashboardEventKind` — wire types
  used by the WebSocket protocol.
"""

from __future__ import annotations

from anglerfish.dashboard.app import (
    create_app,
    default_static_dir,
    default_templates_dir,
)
from anglerfish.dashboard.state import (
    DashboardEvent,
    DashboardEventKind,
    DashboardState,
    DashboardStats,
)

__all__ = [
    "DashboardEvent",
    "DashboardEventKind",
    "DashboardState",
    "DashboardStats",
    "create_app",
    "default_static_dir",
    "default_templates_dir",
]
