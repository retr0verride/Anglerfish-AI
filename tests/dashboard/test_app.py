"""Tests for the FastAPI dashboard app — routes + WebSocket."""

from __future__ import annotations

import base64
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr

from anglerfish.config import AnglerfishSettings
from anglerfish.config.models import CredentialsConfig
from anglerfish.credentials import CredentialStore
from anglerfish.dashboard import DashboardState, create_app
from anglerfish.models.session import CommandTurn, ResponseSource, SessionSnapshot
from anglerfish.models.threat import ThreatAssessment


def _snapshot(*, turns: tuple[CommandTurn, ...] = ()) -> SessionSnapshot:
    ts = datetime(2026, 5, 22, tzinfo=UTC)
    return SessionSnapshot(
        session_id=uuid4(),
        source_ip="203.0.113.7",
        username="root",
        fake_hostname="srv-prod-01",
        fake_username="root",
        fake_cwd="/root",
        started_at=ts,
        last_activity_at=ts,
        turns=turns,
    )


def _turn(cmd: str) -> CommandTurn:
    return CommandTurn(
        command=cmd,
        response="",
        source=ResponseSource.AI,
        timestamp=datetime(2026, 5, 22, tzinfo=UTC),
        latency_ms=1.0,
    )


@pytest.fixture
def app_state(dashboard_state: DashboardState) -> DashboardState:
    return dashboard_state


@pytest.fixture
def client(
    settings: AnglerfishSettings,
    app_state: DashboardState,
) -> Iterator[TestClient]:
    # state owns the session store via the dashboard_state fixture;
    # create_app sees state is provided and skips opening its own store.
    app = create_app(settings, state=app_state)
    with TestClient(app) as c:
        yield c


def _portal(client: TestClient) -> Any:
    # client.portal is None until the with-block enters and the portal starts;
    # once we're inside `with TestClient(app) as c:` it is always present.
    portal = client.portal
    assert portal is not None, "TestClient portal is not active"
    return portal


def test_index_renders_template(client: TestClient) -> None:
    r = client.get("/")
    assert r.status_code == 200
    assert "ANGLERFISH" in r.text.upper()


def test_health(client: TestClient) -> None:
    r = client.get("/api/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_stats_empty(client: TestClient) -> None:
    r = client.get("/api/stats")
    assert r.status_code == 200
    body = r.json()
    assert body["active_sessions"] == 0
    assert body["total_commands_observed"] == 0


def test_sessions_lists_active(
    client: TestClient,
    app_state: DashboardState,
) -> None:
    snap = _snapshot(turns=(_turn("whoami"),))
    _portal(client).call(app_state.update_session, snap)
    r = client.get("/api/sessions")
    assert r.status_code == 200
    sessions = r.json()
    assert len(sessions) == 1
    assert sessions[0]["session_id"] == str(snap.session_id)


def test_get_session_404(client: TestClient) -> None:
    r = client.get(f"/api/sessions/{uuid4()}")
    assert r.status_code == 404


def test_get_session_200(client: TestClient, app_state: DashboardState) -> None:
    snap = _snapshot()
    _portal(client).call(app_state.update_session, snap)
    r = client.get(f"/api/sessions/{snap.session_id}")
    assert r.status_code == 200
    assert r.json()["session_id"] == str(snap.session_id)


def test_threats(client: TestClient, app_state: DashboardState) -> None:
    # The threats FK requires the session row exist before recording.
    snap = _snapshot()
    _portal(client).call(app_state.update_session, snap)
    _portal(client).call(
        app_state.record_threat,
        ThreatAssessment(session_id=snap.session_id, score=85),
    )
    r = client.get("/api/threats")
    assert r.status_code == 200
    payload = r.json()
    assert len(payload) == 1
    assert payload[0]["score"] == 85


def test_recent_commands_endpoint(
    client: TestClient,
    app_state: DashboardState,
) -> None:
    _portal(client).call(
        app_state.update_session,
        _snapshot(turns=(_turn("whoami"),)),
    )
    r = client.get("/api/commands?limit=5")
    assert r.status_code == 200
    assert len(r.json()) == 1


def test_credentials_without_store(client: TestClient) -> None:
    r = client.get("/api/credentials")
    assert r.status_code == 200
    body = r.json()
    assert body["configured"] is False
    assert body["records"] == []


def test_credentials_stats_without_store(client: TestClient) -> None:
    r = client.get("/api/credentials/stats")
    assert r.status_code == 200
    assert r.json()["configured"] is False


def test_credentials_with_store(
    settings: AnglerfishSettings,
    tmp_path: Path,
) -> None:
    db = tmp_path / "creds.db"
    cfg = CredentialsConfig(
        database_path=db,
        encryption_key=SecretStr(base64.b64encode(b"\x09" * 32).decode("ascii")),
    )
    store = CredentialStore(cfg)

    async def _populate() -> None:
        await store.open()
        await store.record_attempt(
            source_ip="1.1.1.1",
            username="admin",
            password="hunter2",
            session_id=uuid4(),
            timestamp=datetime(2026, 5, 22, tzinfo=UTC),
        )

    app = create_app(settings, credential_store=store)
    with TestClient(app) as c:
        _portal(c).call(_populate)
        r = c.get("/api/credentials")
        assert r.status_code == 200
        body = r.json()
        assert body["configured"] is True
        assert len(body["records"]) == 1
        r2 = c.get("/api/credentials/stats")
        assert r2.json()["total_attempts"] == 1


def test_websocket_streams_events(
    client: TestClient,
    app_state: DashboardState,
) -> None:
    with client.websocket_connect(
        "/ws/events",
        headers={"origin": "http://127.0.0.1:8420"},
    ) as ws:
        _portal(client).call(
            app_state.update_session,
            _snapshot(turns=(_turn("whoami"),)),
        )
        first = ws.receive_json()
        second = ws.receive_json()
    kinds = {first["kind"], second["kind"]}
    assert "session_started" in kinds
    assert "command" in kinds


def test_create_app_rejects_missing_templates_dir(
    settings: AnglerfishSettings,
    tmp_path: Path,
) -> None:
    with pytest.raises(FileNotFoundError):
        create_app(settings, templates_dir=tmp_path / "does-not-exist")
