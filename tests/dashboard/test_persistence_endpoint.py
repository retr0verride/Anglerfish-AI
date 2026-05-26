"""Tests for the Stage 10 slice 10.4 :code:`GET /api/persistence/state` route."""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from anglerfish.audit import AuditLog
from anglerfish.config import AnglerfishSettings
from anglerfish.dashboard import create_app
from anglerfish.dashboard.state import DashboardState
from anglerfish.models.persistence import PersistenceEvent


@pytest.fixture
def audit_path(tmp_path: Path) -> Path:
    return tmp_path / "audit.jsonl"


@pytest.fixture
def client(
    settings: AnglerfishSettings,
    audit_path: Path,
    dashboard_state: DashboardState,
) -> Iterator[TestClient]:
    audit = AuditLog(audit_path)
    app = create_app(settings, state=dashboard_state, audit=audit)
    with TestClient(app) as c:
        yield c


# ---------------------------------------------------------------------------
# Empty / valid query
# ---------------------------------------------------------------------------


def test_persistence_state_empty_when_no_rows(client: TestClient) -> None:
    body = client.get("/api/persistence/state?source_ip=203.0.113.7").json()
    assert body == {
        "source_ip": "203.0.113.7",
        "count": 0,
        "items": [],
    }


async def test_persistence_state_returns_rows_oldest_first(
    client: TestClient,
    dashboard_state: DashboardState,
) -> None:
    # Seed two installs at distinct timestamps; the route must
    # return them oldest-first.
    await dashboard_state.record_persistence_event(
        PersistenceEvent(
            kind="crontab",
            sub_key=None,
            payload="0 * * * * /tmp/.first",
            source="regex",
        ),
        source_ip="203.0.113.7",
        session_id=uuid4(),
        created_at=datetime(2026, 5, 25, 12, 0, tzinfo=UTC),
    )
    await dashboard_state.record_persistence_event(
        PersistenceEvent(
            kind="systemctl",
            sub_key="backdoor.service",
            payload="backdoor.service",
            source="llm",
        ),
        source_ip="203.0.113.7",
        session_id=uuid4(),
        created_at=datetime(2026, 5, 26, 12, 0, tzinfo=UTC),
    )
    body = client.get("/api/persistence/state?source_ip=203.0.113.7").json()
    assert body["count"] == 2
    assert body["items"][0]["payload"] == "0 * * * * /tmp/.first"
    assert body["items"][1]["kind"] == "systemctl"
    assert body["items"][1]["source"] == "llm"


async def test_persistence_state_filters_by_source_ip(
    client: TestClient,
    dashboard_state: DashboardState,
) -> None:
    await dashboard_state.record_persistence_event(
        PersistenceEvent(
            kind="crontab",
            sub_key=None,
            payload="for-ip-7",
            source="regex",
        ),
        source_ip="203.0.113.7",
        session_id=uuid4(),
        created_at=datetime(2026, 5, 26, 12, 0, tzinfo=UTC),
    )
    await dashboard_state.record_persistence_event(
        PersistenceEvent(
            kind="crontab",
            sub_key=None,
            payload="for-ip-8",
            source="regex",
        ),
        source_ip="203.0.113.8",
        session_id=uuid4(),
        created_at=datetime(2026, 5, 26, 12, 0, tzinfo=UTC),
    )
    body_7 = client.get("/api/persistence/state?source_ip=203.0.113.7").json()
    body_8 = client.get("/api/persistence/state?source_ip=203.0.113.8").json()
    assert [it["payload"] for it in body_7["items"]] == ["for-ip-7"]
    assert [it["payload"] for it in body_8["items"]] == ["for-ip-8"]


def test_persistence_state_rejects_missing_source_ip(client: TestClient) -> None:
    r = client.get("/api/persistence/state")
    assert r.status_code == 422


def test_persistence_state_rejects_oversize_source_ip(client: TestClient) -> None:
    r = client.get("/api/persistence/state?source_ip=" + "1" * 65)
    assert r.status_code == 422
