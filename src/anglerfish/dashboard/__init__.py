"""FastAPI + WebSocket dashboard.

Public surface:

* :func:`create_app` — FastAPI app factory.
* :class:`DashboardState` — facade over :class:`SessionStore` plus
  an in-process WebSocket pub/sub. ``update_session`` /
  ``record_threat`` / ``end_session`` write through to the store
  and publish to subscribers. The pub/sub is ephemeral; the
  WebSocket endpoint consumes via :meth:`DashboardState.subscribe`.

  As of Stage 4 there is no production writer wired into the
  dashboard process. The bridge tracks sessions in its own in-
  memory dict and does not push events to DashboardState. Stage
  4.2 introduces a bridge→dashboard sink (forwarder-routed HTTP
  push) so the store and pub/sub actually see production traffic.
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
