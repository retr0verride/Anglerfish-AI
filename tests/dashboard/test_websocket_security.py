"""Tests for the WebSocket endpoint's origin + auth guards."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr
from starlette.websockets import WebSocketDisconnect

from anglerfish.config import AnglerfishSettings
from anglerfish.config.models import CredentialsConfig, DashboardConfig
from anglerfish.dashboard import DashboardState, create_app
from anglerfish.dashboard.auth import hash_password

_PASSWORD = "correct horse battery staple"


def _settings(
    session_secret: str,
    encryption_key_b64: str,
    *,
    password: str | None = _PASSWORD,
    allowed_origins: tuple[str, ...] = (),
    port: int = 8420,
) -> AnglerfishSettings:
    password_hash = SecretStr(hash_password(password)) if password else None
    return AnglerfishSettings(
        dashboard=DashboardConfig(
            session_secret=SecretStr(session_secret),
            admin_password_hash=password_hash,
            allowed_origins=allowed_origins,
            port=port,
        ),
        credentials=CredentialsConfig(encryption_key=SecretStr(encryption_key_b64)),
    )


@pytest.fixture
def open_client(
    session_secret: str,
    encryption_key_b64: str,
) -> Iterator[TestClient]:
    settings = _settings(session_secret, encryption_key_b64, password=None)
    with TestClient(create_app(settings, state=DashboardState())) as c:
        yield c


@pytest.fixture
def authed_client(
    session_secret: str,
    encryption_key_b64: str,
) -> Iterator[TestClient]:
    settings = _settings(session_secret, encryption_key_b64)
    with TestClient(create_app(settings, state=DashboardState())) as c:
        yield c


def _login(client: TestClient) -> None:
    r = client.post(
        "/api/login",
        json={"username": "admin", "password": _PASSWORD},
    )
    assert r.status_code == 200


def _connect_expecting_close(client: TestClient, **kwargs: Any) -> int:
    """Open a WS connection that should be rejected; return the close code."""
    try:
        with client.websocket_connect("/ws/events", **kwargs):
            pytest.fail("WebSocket should have been rejected")
    except WebSocketDisconnect as exc:
        return exc.code
    raise AssertionError("unreachable")


# ---------------------------------------------------------------------------
# Origin check
# ---------------------------------------------------------------------------


def test_missing_origin_rejected(open_client: TestClient) -> None:
    code = _connect_expecting_close(open_client)
    assert code == 4403


def test_unknown_origin_rejected(open_client: TestClient) -> None:
    code = _connect_expecting_close(
        open_client,
        headers={"origin": "https://evil.example"},
    )
    assert code == 4403


def test_default_origin_accepted_in_open_mode(open_client: TestClient) -> None:
    with open_client.websocket_connect(
        "/ws/events",
        headers={"origin": "http://127.0.0.1:8420"},
    ):
        pass  # success — accepted


def test_custom_allowed_origin_accepted(
    session_secret: str,
    encryption_key_b64: str,
) -> None:
    settings = _settings(
        session_secret,
        encryption_key_b64,
        password=None,
        allowed_origins=("https://dash.example",),
    )
    with (
        TestClient(create_app(settings, state=DashboardState())) as c,
        c.websocket_connect(
            "/ws/events",
            headers={"origin": "https://dash.example"},
        ),
    ):
        pass  # success


# ---------------------------------------------------------------------------
# Auth check (locked mode only)
# ---------------------------------------------------------------------------


def test_locked_mode_rejects_unauthenticated_ws(authed_client: TestClient) -> None:
    code = _connect_expecting_close(
        authed_client,
        headers={"origin": "http://127.0.0.1:8420"},
    )
    assert code == 4401


def test_locked_mode_accepts_authenticated_ws(authed_client: TestClient) -> None:
    _login(authed_client)
    with authed_client.websocket_connect(
        "/ws/events",
        headers={"origin": "http://127.0.0.1:8420"},
    ):
        pass  # success — both checks passed


def test_locked_mode_logout_invalidates_ws(authed_client: TestClient) -> None:
    _login(authed_client)
    authed_client.post("/api/logout")
    code = _connect_expecting_close(
        authed_client,
        headers={"origin": "http://127.0.0.1:8420"},
    )
    assert code == 4401


def test_origin_check_runs_before_auth_check(authed_client: TestClient) -> None:
    """Bad origin gets the BAD_ORIGIN code, not the POLICY_VIOLATION code."""
    code = _connect_expecting_close(
        authed_client,
        headers={"origin": "https://evil.example"},
    )
    assert code == 4403  # not 4401
