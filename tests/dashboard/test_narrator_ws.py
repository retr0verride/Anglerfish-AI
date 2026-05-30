"""Stage 13 slice 13.5b: narrator events ride the /ws/events bus."""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from anglerfish.audit import AuditLog
from anglerfish.config import AnglerfishSettings
from anglerfish.dashboard import create_app
from anglerfish.dashboard.state import DashboardEvent, DashboardEventKind, DashboardState

_ORIGIN = {"origin": "http://127.0.0.1:8420"}
_AT = datetime(2026, 5, 29, 12, 0, tzinfo=UTC)


@pytest.fixture
def client_and_state(
    settings: AnglerfishSettings,
    tmp_path: Path,
    dashboard_state: DashboardState,
) -> Iterator[tuple[TestClient, DashboardState]]:
    audit = AuditLog(tmp_path / "audit.jsonl")
    app = create_app(settings, state=dashboard_state, audit=audit)
    with TestClient(app) as c:
        yield c, dashboard_state


def _narrator_event() -> DashboardEvent:
    return DashboardEvent(
        kind=DashboardEventKind.NARRATOR,
        timestamp=_AT,
        payload={
            "session_id": "7f3a1b2c",
            "text": "Attacker is enumerating cron and systemd.",
            "ts": _AT.isoformat(),
            "model": "qwen3:14b",
        },
    )


def test_narrator_event_reaches_ws_client(
    client_and_state: tuple[TestClient, DashboardState],
) -> None:
    client, state = client_and_state
    portal = client.portal
    assert portal is not None
    with client.websocket_connect("/ws/events", headers=_ORIGIN) as ws:
        # Publish on the app's event loop while the client is subscribed.
        portal.call(state.publish, _narrator_event())
        msg = ws.receive_json()
    assert msg["kind"] == "narrator"
    assert msg["payload"]["text"] == "Attacker is enumerating cron and systemd."
    assert msg["payload"]["session_id"] == "7f3a1b2c"
    assert msg["payload"]["model"] == "qwen3:14b"
