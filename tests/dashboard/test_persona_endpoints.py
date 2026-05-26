"""Tests for the Stage 9 slice 9.4 dashboard persona-pin routes."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr

from anglerfish.audit import AuditLog
from anglerfish.config import AnglerfishSettings
from anglerfish.config.models import DashboardConfig
from anglerfish.dashboard import create_app
from anglerfish.dashboard.auth import hash_password
from anglerfish.persona import PersonaRegistry
from anglerfish.persona.schema import Persona

_TEST_USERNAME = "operator"
_TEST_PASSWORD = "correct horse battery staple"


def _settings_with_auth(base: AnglerfishSettings) -> AnglerfishSettings:
    pwd_hash = hash_password(_TEST_PASSWORD)
    return base.model_copy(
        update={
            "dashboard": DashboardConfig(
                session_secret=base.dashboard.session_secret,
                admin_username=_TEST_USERNAME,
                admin_password_hash=SecretStr(pwd_hash),
            ),
        },
    )


def _persona(name: str) -> Persona:
    return Persona(
        name=name,
        description=f"The {name} persona.",
        hostname=name,
        username="root",
        cwd="/root",
        prompt_block=f"{name} block.",
    )


@pytest.fixture
def registry() -> PersonaRegistry:
    return PersonaRegistry(
        {
            "forgotten-debian-box": _persona("forgotten-debian-box"),
            "gpu-rig": _persona("gpu-rig"),
            "dev-laptop": _persona("dev-laptop"),
        },
    )


@pytest.fixture
def authed_client(
    settings: AnglerfishSettings,
    tmp_path: Path,
    registry: PersonaRegistry,
) -> Iterator[tuple[TestClient, Path]]:
    """Authenticated TestClient + the path to its audit log."""
    audit_path = tmp_path / "audit.jsonl"
    audit = AuditLog(audit_path)
    app = create_app(
        _settings_with_auth(settings),
        audit=audit,
        persona_registry=registry,
    )
    with TestClient(app) as c:
        login = c.post(
            "/api/login",
            json={"username": _TEST_USERNAME, "password": _TEST_PASSWORD},
        )
        assert login.status_code == 200, login.text
        csrf = c.get("/api/csrf")
        c.headers["X-Anglerfish-CSRF"] = csrf.json()["token"]
        yield c, audit_path


# ---------------------------------------------------------------------------
# POST /api/persona/pin
# ---------------------------------------------------------------------------


def test_pin_requires_auth(
    settings: AnglerfishSettings,
    registry: PersonaRegistry,
) -> None:
    app = create_app(_settings_with_auth(settings), persona_registry=registry)
    with TestClient(app) as c:
        r = c.post(
            "/api/persona/pin",
            json={"source_ip": "203.0.113.7", "persona": "gpu-rig"},
        )
    assert r.status_code in (401, 403)


def test_pin_persists_and_audits(
    authed_client: tuple[TestClient, Path],
) -> None:
    client, audit_path = authed_client
    r = client.post(
        "/api/persona/pin",
        json={"source_ip": "203.0.113.7", "persona": "gpu-rig"},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["source_ip"] == "203.0.113.7"
    assert body["persona"] == "gpu-rig"
    assert body["created_by"] == _TEST_USERNAME
    text = audit_path.read_text(encoding="utf-8")
    assert '"event_type":"dashboard.persona_pinned"' in text
    assert '"persona":"gpu-rig"' in text


def test_pin_rejects_unknown_persona(
    authed_client: tuple[TestClient, Path],
) -> None:
    client, _ = authed_client
    r = client.post(
        "/api/persona/pin",
        json={"source_ip": "203.0.113.7", "persona": "does-not-exist"},
    )
    assert r.status_code == 422


def test_pin_rejects_malformed_persona_pattern(
    authed_client: tuple[TestClient, Path],
) -> None:
    client, _ = authed_client
    # Capital letters violate Persona.name pattern -> Pydantic 422.
    r = client.post(
        "/api/persona/pin",
        json={"source_ip": "203.0.113.7", "persona": "GPU-RIG"},
    )
    assert r.status_code == 422


def test_pin_overwrites_existing_for_same_ip(
    authed_client: tuple[TestClient, Path],
) -> None:
    client, _ = authed_client
    client.post(
        "/api/persona/pin",
        json={"source_ip": "203.0.113.7", "persona": "gpu-rig"},
    )
    r = client.post(
        "/api/persona/pin",
        json={"source_ip": "203.0.113.7", "persona": "dev-laptop"},
    )
    assert r.status_code == 200
    assert r.json()["persona"] == "dev-laptop"
    listing = client.get("/api/persona/pin").json()
    assert listing["count"] == 1
    assert listing["items"][0]["persona"] == "dev-laptop"


def test_pin_returns_503_when_registry_disabled(
    settings: AnglerfishSettings,
) -> None:
    """settings.persona.enabled=False -> registry is None -> 503."""
    from anglerfish.config.models import PersonaConfig

    disabled = _settings_with_auth(settings).model_copy(
        update={"persona": PersonaConfig(enabled=False)},
    )
    app = create_app(disabled)
    with TestClient(app) as c:
        login = c.post(
            "/api/login",
            json={"username": _TEST_USERNAME, "password": _TEST_PASSWORD},
        )
        assert login.status_code == 200
        c.headers["X-Anglerfish-CSRF"] = c.get("/api/csrf").json()["token"]
        r = c.post(
            "/api/persona/pin",
            json={"source_ip": "203.0.113.7", "persona": "gpu-rig"},
        )
    assert r.status_code == 503


# ---------------------------------------------------------------------------
# GET /api/persona/pin
# ---------------------------------------------------------------------------


def test_list_empty_when_no_pins(
    authed_client: tuple[TestClient, Path],
) -> None:
    client, _ = authed_client
    body = client.get("/api/persona/pin").json()
    assert body == {"count": 0, "items": []}


def test_list_returns_pins_newest_first(
    authed_client: tuple[TestClient, Path],
) -> None:
    client, _ = authed_client
    client.post(
        "/api/persona/pin",
        json={"source_ip": "203.0.113.1", "persona": "gpu-rig"},
    )
    client.post(
        "/api/persona/pin",
        json={"source_ip": "203.0.113.2", "persona": "dev-laptop"},
    )
    body = client.get("/api/persona/pin").json()
    assert body["count"] == 2
    # Newest first: dev-laptop was posted second.
    assert body["items"][0]["source_ip"] == "203.0.113.2"


# ---------------------------------------------------------------------------
# DELETE /api/persona/pin/<source_ip>
# ---------------------------------------------------------------------------


def test_delete_existing_returns_204_and_audits(
    authed_client: tuple[TestClient, Path],
) -> None:
    client, audit_path = authed_client
    client.post(
        "/api/persona/pin",
        json={"source_ip": "203.0.113.7", "persona": "gpu-rig"},
    )
    r = client.delete("/api/persona/pin/203.0.113.7")
    assert r.status_code == 204
    assert "dashboard.persona_unpinned" in audit_path.read_text(encoding="utf-8")
    assert client.get("/api/persona/pin").json()["count"] == 0


def test_delete_unknown_returns_404(
    authed_client: tuple[TestClient, Path],
) -> None:
    client, _ = authed_client
    r = client.delete("/api/persona/pin/203.0.113.99")
    assert r.status_code == 404


def test_delete_requires_csrf(
    settings: AnglerfishSettings,
    registry: PersonaRegistry,
) -> None:
    """No CSRF header -> reject."""
    app = create_app(_settings_with_auth(settings), persona_registry=registry)
    with TestClient(app) as c:
        login = c.post(
            "/api/login",
            json={"username": _TEST_USERNAME, "password": _TEST_PASSWORD},
        )
        assert login.status_code == 200
        # Skip the CSRF header on purpose.
        r = c.delete("/api/persona/pin/203.0.113.7")
    assert r.status_code in (401, 403)
