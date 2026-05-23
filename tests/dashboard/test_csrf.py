"""Tests for the CSRF helpers."""

from __future__ import annotations

import pytest
from fastapi import FastAPI, HTTPException, Request
from starlette.middleware.sessions import SessionMiddleware
from starlette.testclient import TestClient

from anglerfish.dashboard.csrf import CSRF_HEADER, CSRF_SESSION_KEY, issue_token, require_csrf


def _app() -> FastAPI:
    app = FastAPI()
    app.add_middleware(SessionMiddleware, secret_key="x" * 32, same_site="strict")

    @app.get("/seed")
    async def seed(request: Request) -> dict[str, str]:
        return {"token": issue_token(request)}

    @app.post("/protected")
    async def protected(request: Request) -> dict[str, str]:
        require_csrf(request)
        return {"status": "ok"}

    return app


def test_issue_token_is_idempotent_within_session() -> None:
    client = TestClient(_app())
    first = client.get("/seed").json()["token"]
    second = client.get("/seed").json()["token"]
    assert first == second
    assert len(first) >= 32


def test_protected_endpoint_rejects_missing_token() -> None:
    client = TestClient(_app())
    # Seed a session cookie first so a CSRF token *exists* — the
    # rejection is for the missing header.
    client.get("/seed")
    resp = client.post("/protected")
    assert resp.status_code == 403
    assert "csrf" in resp.json()["detail"].lower()


def test_protected_endpoint_rejects_wrong_token() -> None:
    client = TestClient(_app())
    client.get("/seed")
    resp = client.post("/protected", headers={CSRF_HEADER: "definitely-wrong"})
    assert resp.status_code == 403


def test_protected_endpoint_accepts_valid_token() -> None:
    client = TestClient(_app())
    token = client.get("/seed").json()["token"]
    resp = client.post("/protected", headers={CSRF_HEADER: token})
    assert resp.status_code == 200


def test_protected_endpoint_rejects_when_no_session_yet() -> None:
    """Without a prior /seed there is no session token at all."""
    client = TestClient(_app())
    resp = client.post(
        "/protected",
        headers={CSRF_HEADER: "anything"},
    )
    assert resp.status_code == 403
    assert "missing csrf token" in resp.json()["detail"].lower()


def test_csrf_session_key_is_stable() -> None:
    # Pin the name so a rename doesn't silently invalidate every operator's session.
    assert CSRF_SESSION_KEY == "csrf_token"


def test_require_csrf_raises_http_exception_when_called_directly() -> None:
    """Calling require_csrf without a Request shape raises cleanly."""

    class _StubSession(dict):  # type: ignore[type-arg]
        pass

    class _StubRequest:
        session = _StubSession()
        headers: dict[str, str] = {}

    with pytest.raises(HTTPException) as exc:
        require_csrf(_StubRequest())  # type: ignore[arg-type]
    assert exc.value.status_code == 403
