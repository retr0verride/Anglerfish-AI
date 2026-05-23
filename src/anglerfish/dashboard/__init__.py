"""FastAPI + WebSocket dashboard.

Public surface:

* :func:`create_app` — FastAPI app factory.
* :class:`DashboardState` — in-memory pub/sub + bounded cache; the
  bridge and threat engine call its ``update_session`` /
  ``record_threat`` methods to publish, and the WebSocket endpoint
  consumes via :meth:`DashboardState.subscribe`.
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
