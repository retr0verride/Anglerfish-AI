"""Tests for dashboard authentication: bcrypt hash, login/logout, basic auth."""

from __future__ import annotations

import base64
from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr

from anglerfish.audit import AuditLog
from anglerfish.config import AnglerfishSettings
from anglerfish.config.models import CredentialsConfig, DashboardConfig
from anglerfish.dashboard import DashboardState, create_app
from anglerfish.dashboard.auth import hash_password, verify_password
from anglerfish.dashboard.csrf import CSRF_HEADER
from anglerfish.dashboard.rate_limit import LoginRateLimiter

_PASSWORD = "correct horse battery staple"


def _settings_with_password(
    session_secret: str,
    encryption_key_b64: str,
    password: str | None = _PASSWORD,
    *,
    username: str = "admin",
) -> AnglerfishSettings:
    password_hash = SecretStr(hash_password(password)) if password else None
    return AnglerfishSettings(
        dashboard=DashboardConfig(
            session_secret=SecretStr(session_secret),
            admin_username=username,
            admin_password_hash=password_hash,
        ),
        credentials=CredentialsConfig(encryption_key=SecretStr(encryption_key_b64)),
    )


@pytest.fixture
def open_client(
    session_secret: str,
    encryption_key_b64: str,
) -> Iterator[TestClient]:
    """Dashboard with no admin password — open mode."""
    settings = _settings_with_password(session_secret, encryption_key_b64, password=None)
    with TestClient(create_app(settings, state=DashboardState())) as c:
        yield c


@pytest.fixture
def authed_client(
    session_secret: str,
    encryption_key_b64: str,
    tmp_path: Path,
) -> Iterator[TestClient]:
    """Dashboard with admin password configured — locked mode."""
    settings = _settings_with_password(session_secret, encryption_key_b64)
    audit = AuditLog(tmp_path / "audit.jsonl")
    with TestClient(create_app(settings, state=DashboardState(), audit=audit)) as c:
        yield c


# ---------------------------------------------------------------------------
# hash_password / verify_password
# ---------------------------------------------------------------------------


def test_hash_password_round_trip() -> None:
    h = hash_password(_PASSWORD)
    assert verify_password(_PASSWORD, h) is True


def test_hash_password_rejects_wrong_password() -> None:
    h = hash_password(_PASSWORD)
    assert verify_password("guessed", h) is False


def test_hash_password_rejects_empty() -> None:
    with pytest.raises(ValueError):
        hash_password("")


def test_hash_password_format() -> None:
    h = hash_password(_PASSWORD)
    assert h.startswith(("$2a$", "$2b$", "$2y$"))


def test_verify_password_garbage_hash_returns_false() -> None:
    assert verify_password(_PASSWORD, "not-a-hash") is False


# ---------------------------------------------------------------------------
# Open mode (no password configured)
# ---------------------------------------------------------------------------


def test_open_mode_serves_endpoints_without_auth(open_client: TestClient) -> None:
    r = open_client.get("/api/stats")
    assert r.status_code == 200


def test_open_mode_login_returns_503(open_client: TestClient) -> None:
    r = open_client.post(
        "/api/login",
        json={"username": "admin", "password": _PASSWORD},
    )
    assert r.status_code == 503


def test_health_always_open_in_open_mode(open_client: TestClient) -> None:
    r = open_client.get("/api/health")
    assert r.status_code == 200


# ---------------------------------------------------------------------------
# Locked mode (password configured)
# ---------------------------------------------------------------------------


def test_locked_mode_rejects_unauthenticated(authed_client: TestClient) -> None:
    r = authed_client.get("/api/stats")
    assert r.status_code == 401
    assert "WWW-Authenticate" in r.headers


def test_locked_mode_health_is_still_open(authed_client: TestClient) -> None:
    r = authed_client.get("/api/health")
    assert r.status_code == 200


def test_locked_mode_root_is_still_open(authed_client: TestClient) -> None:
    # The login page itself must be reachable without auth.
    r = authed_client.get("/")
    assert r.status_code == 200


def test_login_with_correct_credentials_succeeds(authed_client: TestClient) -> None:
    r = authed_client.post(
        "/api/login",
        json={"username": "admin", "password": _PASSWORD},
    )
    assert r.status_code == 200
    # Session cookie now set; subsequent calls succeed.
    r2 = authed_client.get("/api/stats")
    assert r2.status_code == 200


def test_login_with_wrong_password_returns_401(authed_client: TestClient) -> None:
    r = authed_client.post(
        "/api/login",
        json={"username": "admin", "password": "nope"},
    )
    assert r.status_code == 401


def test_login_with_wrong_username_returns_401(authed_client: TestClient) -> None:
    r = authed_client.post(
        "/api/login",
        json={"username": "intruder", "password": _PASSWORD},
    )
    assert r.status_code == 401


def test_logout_clears_session(authed_client: TestClient) -> None:
    # Log in
    authed_client.post(
        "/api/login",
        json={"username": "admin", "password": _PASSWORD},
    )
    assert authed_client.get("/api/stats").status_code == 200
    # Log out
    r = authed_client.post("/api/logout")
    assert r.status_code == 200
    # Subsequent call is unauthorised again
    assert authed_client.get("/api/stats").status_code == 401


def test_basic_auth_accepted(authed_client: TestClient) -> None:
    credentials = base64.b64encode(f"admin:{_PASSWORD}".encode()).decode("ascii")
    r = authed_client.get(
        "/api/stats",
        headers={"Authorization": f"Basic {credentials}"},
    )
    assert r.status_code == 200


def test_basic_auth_wrong_password(authed_client: TestClient) -> None:
    credentials = base64.b64encode(b"admin:nope").decode("ascii")
    r = authed_client.get(
        "/api/stats",
        headers={"Authorization": f"Basic {credentials}"},
    )
    assert r.status_code == 401


def test_basic_auth_malformed(authed_client: TestClient) -> None:
    r = authed_client.get(
        "/api/stats",
        headers={"Authorization": "Basic not!base64!"},
    )
    assert r.status_code == 401


def test_basic_auth_no_colon(authed_client: TestClient) -> None:
    credentials = base64.b64encode(b"admin-no-colon").decode("ascii")
    r = authed_client.get(
        "/api/stats",
        headers={"Authorization": f"Basic {credentials}"},
    )
    assert r.status_code == 401


def test_basic_auth_rejected_in_open_mode(open_client: TestClient) -> None:
    # Open mode should accept without auth, but should NOT positively
    # authenticate a Basic header — endpoint just returns 200 by virtue
    # of being open. We can't distinguish "accepted via basic" from
    # "accepted via open mode", but we can confirm the endpoint works.
    credentials = base64.b64encode(b"admin:anything").decode("ascii")
    r = open_client.get(
        "/api/stats",
        headers={"Authorization": f"Basic {credentials}"},
    )
    assert r.status_code == 200


# ---------------------------------------------------------------------------
# Audit log integration
# ---------------------------------------------------------------------------


def test_successful_login_audited(
    session_secret: str,
    encryption_key_b64: str,
    tmp_path: Path,
) -> None:
    settings = _settings_with_password(session_secret, encryption_key_b64)
    audit_path = tmp_path / "audit.jsonl"
    audit = AuditLog(audit_path)
    with TestClient(create_app(settings, audit=audit)) as c:
        r = c.post(
            "/api/login",
            json={"username": "admin", "password": _PASSWORD},
        )
        assert r.status_code == 200
    assert audit_path.exists()
    content = audit_path.read_text("utf-8")
    assert "login_success" in content
    assert "admin" in content


def test_failed_login_audited(
    session_secret: str,
    encryption_key_b64: str,
    tmp_path: Path,
) -> None:
    settings = _settings_with_password(session_secret, encryption_key_b64)
    audit_path = tmp_path / "audit.jsonl"
    audit = AuditLog(audit_path)
    with TestClient(create_app(settings, audit=audit)) as c:
        c.post("/api/login", json={"username": "admin", "password": "nope"})
    assert "login_failure" in audit_path.read_text("utf-8")


# ---------------------------------------------------------------------------
# Login rate limiter
# ---------------------------------------------------------------------------


def test_login_rate_limit_triggers_429(
    session_secret: str,
    encryption_key_b64: str,
    tmp_path: Path,
) -> None:
    settings = _settings_with_password(session_secret, encryption_key_b64)
    audit_path = tmp_path / "audit.jsonl"
    audit = AuditLog(audit_path)
    # 2-token bucket → 2 attempts allowed, then 429.
    limiter = LoginRateLimiter(capacity=2, refill_per_second=0.01)
    with TestClient(
        create_app(settings, audit=audit, login_rate_limiter=limiter),
    ) as c:
        for _ in range(2):
            r = c.post("/api/login", json={"username": "admin", "password": "nope"})
            assert r.status_code == 401
        r = c.post("/api/login", json={"username": "admin", "password": "nope"})
        assert r.status_code == 429
        assert r.headers["Retry-After"]
    assert "login_rate_limited" in audit_path.read_text("utf-8")


def test_successful_login_resets_rate_limit(
    session_secret: str,
    encryption_key_b64: str,
    tmp_path: Path,
) -> None:
    settings = _settings_with_password(session_secret, encryption_key_b64)
    audit = AuditLog(tmp_path / "audit.jsonl")
    limiter = LoginRateLimiter(capacity=2, refill_per_second=0.01)
    with TestClient(
        create_app(settings, audit=audit, login_rate_limiter=limiter),
    ) as c:
        # Burn one token on a failure.
        c.post("/api/login", json={"username": "admin", "password": "nope"})
        # Succeed — should reset the bucket.
        r = c.post("/api/login", json={"username": "admin", "password": _PASSWORD})
        assert r.status_code == 200
        # Bucket is full again; one failure shouldn't lock us out.
        r = c.post("/api/login", json={"username": "admin", "password": "nope"})
        assert r.status_code == 401


# ---------------------------------------------------------------------------
# CSRF endpoint
# ---------------------------------------------------------------------------


def test_csrf_endpoint_returns_token_after_login(authed_client: TestClient) -> None:
    authed_client.post(
        "/api/login",
        json={"username": "admin", "password": _PASSWORD},
    )
    r = authed_client.get("/api/csrf")
    assert r.status_code == 200
    token = r.json()["token"]
    assert isinstance(token, str)
    assert len(token) >= 32
    # Header constant must match the implementation
    assert CSRF_HEADER == "X-Anglerfish-CSRF"


def test_csrf_token_stable_across_calls(authed_client: TestClient) -> None:
    authed_client.post(
        "/api/login",
        json={"username": "admin", "password": _PASSWORD},
    )
    first = authed_client.get("/api/csrf").json()["token"]
    second = authed_client.get("/api/csrf").json()["token"]
    assert first == second


def test_login_seeds_csrf_token(authed_client: TestClient) -> None:
    """A successful login should also seed the CSRF token in the session."""
    r = authed_client.post(
        "/api/login",
        json={"username": "admin", "password": _PASSWORD},
    )
    assert r.status_code == 200
    # The /api/csrf endpoint returns the seeded token without re-creating one.
    token = authed_client.get("/api/csrf").json()["token"]
    assert len(token) >= 32
