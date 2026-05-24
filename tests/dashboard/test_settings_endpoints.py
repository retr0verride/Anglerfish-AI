"""Tests for the Stage 3 settings control plane endpoints."""

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

# Tests need an authenticated session AND a CSRF token. Hash a real
# password into the dashboard config so /api/login + /api/csrf both
# work; the existing open-mode fixture would bypass CSRF entirely
# which is the wrong test surface.
_TEST_USERNAME = "operator"
_TEST_PASSWORD = "correct horse battery staple"


def _settings_with_auth(
    base_settings: AnglerfishSettings,
) -> AnglerfishSettings:
    pwd_hash = hash_password(_TEST_PASSWORD)
    return base_settings.model_copy(
        update={
            "dashboard": DashboardConfig(
                session_secret=base_settings.dashboard.session_secret,
                admin_username=_TEST_USERNAME,
                admin_password_hash=SecretStr(pwd_hash),
            ),
        },
    )


@pytest.fixture
def authed_client(
    settings: AnglerfishSettings,
    tmp_path: Path,
) -> Iterator[TestClient]:
    """Authenticated client with a CSRF token already in the session."""
    audit = AuditLog(tmp_path / "audit.jsonl")
    app = create_app(_settings_with_auth(settings), audit=audit)
    with TestClient(app) as c:
        login = c.post(
            "/api/login",
            json={"username": _TEST_USERNAME, "password": _TEST_PASSWORD},
        )
        assert login.status_code == 200, login.text
        csrf = c.get("/api/csrf")
        assert csrf.status_code == 200
        c.headers["X-Anglerfish-CSRF"] = csrf.json()["token"]
        yield c


@pytest.fixture
def authed_client_and_audit(
    settings: AnglerfishSettings,
    tmp_path: Path,
) -> Iterator[tuple[TestClient, Path]]:
    """Variant that also exposes the audit-log path for assertions."""
    audit_path = tmp_path / "audit.jsonl"
    audit = AuditLog(audit_path)
    app = create_app(_settings_with_auth(settings), audit=audit)
    with TestClient(app) as c:
        login = c.post(
            "/api/login",
            json={"username": _TEST_USERNAME, "password": _TEST_PASSWORD},
        )
        assert login.status_code == 200
        csrf = c.get("/api/csrf")
        c.headers["X-Anglerfish-CSRF"] = csrf.json()["token"]
        yield c, audit_path


# ---------------------------------------------------------------------------
# GET /api/settings
# ---------------------------------------------------------------------------


def test_get_settings_returns_provenance_fields(authed_client: TestClient) -> None:
    r = authed_client.get("/api/settings")
    assert r.status_code == 200
    body = r.json()
    assert body["applies_to"] == "dashboard_process"
    assert "Service restart" in body["note"]
    assert "applied_at" in body
    assert "bridge" in body
    assert "features" in body
    assert body["bridge"]["wasting_strategy"] == "off"


def test_get_settings_requires_auth(settings: AnglerfishSettings) -> None:
    # Use the auth-enabled settings but DON'T log in.
    app = create_app(_settings_with_auth(settings))
    with TestClient(app) as c:
        r = c.get("/api/settings")
        assert r.status_code == 401


# ---------------------------------------------------------------------------
# POST /api/settings/bridge
# ---------------------------------------------------------------------------


def test_post_bridge_settings_updates_and_returns_new_state(
    authed_client: TestClient,
) -> None:
    r = authed_client.post(
        "/api/settings/bridge",
        json={"max_concurrent_requests": 16, "wasting_strategy": "light"},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["bridge"]["max_concurrent_requests"] == 16
    assert body["bridge"]["wasting_strategy"] == "light"
    assert "max_concurrent_requests" in body["changed_fields"]
    assert "wasting_strategy" in body["changed_fields"]


def test_post_bridge_settings_partial_update_keeps_other_fields(
    authed_client: TestClient,
) -> None:
    authed_client.post(
        "/api/settings/bridge",
        json={"max_concurrent_requests": 4},
    )
    r = authed_client.get("/api/settings")
    body = r.json()
    assert body["bridge"]["max_concurrent_requests"] == 4
    # Defaulted rate-limit settings preserved.
    assert body["bridge"]["requests_per_session_per_minute"] == 30


def test_post_bridge_settings_rejects_out_of_bounds(
    authed_client: TestClient,
) -> None:
    r = authed_client.post(
        "/api/settings/bridge",
        json={"max_concurrent_requests": 9999},
    )
    assert r.status_code == 422


def test_post_bridge_settings_rejects_unknown_wasting_strategy(
    authed_client: TestClient,
) -> None:
    r = authed_client.post(
        "/api/settings/bridge",
        json={"wasting_strategy": "ludicrous"},
    )
    assert r.status_code == 422


def test_post_bridge_settings_rejects_extra_keys(authed_client: TestClient) -> None:
    r = authed_client.post(
        "/api/settings/bridge",
        json={"bogus_field": "x"},
    )
    assert r.status_code == 422


def test_post_bridge_settings_no_op_no_changed_fields(
    authed_client: TestClient,
) -> None:
    current = authed_client.get("/api/settings").json()
    r = authed_client.post(
        "/api/settings/bridge",
        json={
            "max_concurrent_requests": current["bridge"]["max_concurrent_requests"],
        },
    )
    assert r.status_code == 200
    assert r.json()["changed_fields"] == []


# ---------------------------------------------------------------------------
# POST /api/settings/features
# ---------------------------------------------------------------------------


def test_post_feature_flags_flips_one_flag(authed_client: TestClient) -> None:
    r = authed_client.post(
        "/api/settings/features",
        json={"time_wasting": True},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["features"]["time_wasting"] is True
    assert body["features"]["engaged_persistence"] is False
    assert body["changed_fields"] == ["time_wasting"]


def test_post_feature_flags_no_op_when_unchanged(authed_client: TestClient) -> None:
    # All defaults are False; sending False is a no-op.
    r = authed_client.post(
        "/api/settings/features",
        json={"time_wasting": False},
    )
    assert r.status_code == 200
    assert r.json()["changed_fields"] == []


def test_post_feature_flags_rejects_non_bool(authed_client: TestClient) -> None:
    # Pydantic v2 coerces yes/no/true/false/1/0 to bool, so use an
    # object value to trigger the type-error path.
    r = authed_client.post(
        "/api/settings/features",
        json={"time_wasting": {"nested": "object"}},
    )
    assert r.status_code == 422


# ---------------------------------------------------------------------------
# CSRF
# ---------------------------------------------------------------------------


def test_post_bridge_settings_rejects_missing_csrf_header(
    settings: AnglerfishSettings,
) -> None:
    app = create_app(_settings_with_auth(settings))
    with TestClient(app) as c:
        login = c.post(
            "/api/login",
            json={"username": _TEST_USERNAME, "password": _TEST_PASSWORD},
        )
        assert login.status_code == 200
        # Seed the csrf token on the session so the rejection is for the
        # missing header, not for "no token issued."
        c.get("/api/csrf")
        r = c.post("/api/settings/bridge", json={"max_concurrent_requests": 16})
        assert r.status_code == 403
        assert "csrf" in r.json()["detail"].lower()


def test_post_bridge_settings_rejects_wrong_csrf_token(
    settings: AnglerfishSettings,
) -> None:
    app = create_app(_settings_with_auth(settings))
    with TestClient(app) as c:
        login = c.post(
            "/api/login",
            json={"username": _TEST_USERNAME, "password": _TEST_PASSWORD},
        )
        assert login.status_code == 200
        c.get("/api/csrf")
        r = c.post(
            "/api/settings/bridge",
            json={"max_concurrent_requests": 16},
            headers={"X-Anglerfish-CSRF": "definitely-wrong"},
        )
        assert r.status_code == 403


def test_post_feature_flags_rejects_missing_csrf(
    settings: AnglerfishSettings,
) -> None:
    app = create_app(_settings_with_auth(settings))
    with TestClient(app) as c:
        c.post(
            "/api/login",
            json={"username": _TEST_USERNAME, "password": _TEST_PASSWORD},
        )
        c.get("/api/csrf")
        r = c.post("/api/settings/features", json={"time_wasting": True})
        assert r.status_code == 403


# ---------------------------------------------------------------------------
# Audit events
# ---------------------------------------------------------------------------


def test_settings_change_emits_audit_event(
    authed_client_and_audit: tuple[TestClient, Path],
) -> None:
    client, audit_path = authed_client_and_audit
    r = client.post(
        "/api/settings/bridge",
        json={"max_concurrent_requests": 4},
    )
    assert r.status_code == 200
    events = audit_path.read_text(encoding="utf-8")
    assert "dashboard.settings_changed" in events
    assert "max_concurrent_requests" in events


def test_feature_toggle_emits_audit_event(
    authed_client_and_audit: tuple[TestClient, Path],
) -> None:
    client, audit_path = authed_client_and_audit
    r = client.post(
        "/api/settings/features",
        json={"counter_deception": True},
    )
    assert r.status_code == 200
    events = audit_path.read_text(encoding="utf-8")
    assert "dashboard.feature_toggled" in events
    assert "counter_deception" in events
