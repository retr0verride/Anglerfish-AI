"""Integration test for dashboard -> bridge override propagation (Stage 6)."""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr

from anglerfish.audit import AuditLog
from anglerfish.bridge.overrides_reader import BridgeOverridesReader
from anglerfish.config import (
    AnglerfishSettings,
    BridgeConfig,
    CredentialsConfig,
    DashboardConfig,
)
from anglerfish.config.models import SessionStoreConfig
from anglerfish.dashboard import create_app
from anglerfish.dashboard.auth import hash_password

_TEST_USERNAME = "operator"
_TEST_PASSWORD = "correct horse battery staple"


@pytest.fixture
def overrides_path(tmp_path: Path) -> Path:
    return tmp_path / "runtime_overrides.json"


@pytest.fixture
def propagation_settings(
    tmp_path: Path,
    overrides_path: Path,
    session_secret: str,
    encryption_key_b64: str,
) -> AnglerfishSettings:
    """Settings with publish+poll paths pinned + a hashed admin password.

    The password is set so the dashboard runs locked mode + CSRF
    enforcement; the POST endpoint requires both.
    """
    return AnglerfishSettings(
        dashboard=DashboardConfig(
            session_secret=SecretStr(session_secret),
            admin_username=_TEST_USERNAME,
            admin_password_hash=SecretStr(hash_password(_TEST_PASSWORD)),
            overrides_publish_path=overrides_path,
        ),
        credentials=CredentialsConfig(encryption_key=SecretStr(encryption_key_b64)),
        sessions=SessionStoreConfig(database_path=tmp_path / "sessions.db"),
        bridge=BridgeConfig(overrides_poll_path=overrides_path),
    )


@pytest.fixture
def client(
    propagation_settings: AnglerfishSettings,
    tmp_path: Path,
) -> Iterator[TestClient]:
    """Authenticated client with a CSRF token already in the session."""
    audit = AuditLog(tmp_path / "audit.jsonl")
    with TestClient(create_app(propagation_settings, audit=audit)) as c:
        login = c.post(
            "/api/login",
            json={"username": _TEST_USERNAME, "password": _TEST_PASSWORD},
        )
        assert login.status_code == 200, login.text
        csrf = c.get("/api/csrf")
        assert csrf.status_code == 200
        c.headers["X-Anglerfish-CSRF"] = csrf.json()["token"]
        yield c


def test_dashboard_writes_publish_file_on_startup(
    client: TestClient,
    overrides_path: Path,
) -> None:
    # create_app published the initial snapshot (quiet=True) so the file
    # exists with the env-file defaults.
    assert overrides_path.exists()
    payload = json.loads(overrides_path.read_text(encoding="utf-8"))
    assert payload["bridge"]["wasting_strategy"] == "off"


def test_bridge_reader_sees_initial_publish(
    client: TestClient,
    overrides_path: Path,
    propagation_settings: AnglerfishSettings,
) -> None:
    reader = BridgeOverridesReader(
        overrides_path,
        cache_ttl_s=1.0,
        static_fallback=propagation_settings.bridge.wasting_strategy,
    )
    assert reader.current_wasting_strategy() == "off"


def test_dashboard_post_propagates_to_bridge_reader(
    client: TestClient,
    overrides_path: Path,
    propagation_settings: AnglerfishSettings,
) -> None:
    reader = BridgeOverridesReader(
        overrides_path,
        cache_ttl_s=0.001,  # tight TTL so re-poll happens immediately
        static_fallback="off",
    )
    assert reader.current_wasting_strategy() == "off"

    # Operator flips the strategy via the dashboard. The client fixture
    # already attached the X-Anglerfish-CSRF header after login.
    r = client.post(
        "/api/settings/bridge",
        json={"wasting_strategy": "aggressive"},
    )
    assert r.status_code == 200, r.text

    # The file on disk reflects the change.
    payload = json.loads(overrides_path.read_text(encoding="utf-8"))
    assert payload["bridge"]["wasting_strategy"] == "aggressive"

    # Sleep past the reader's TTL so the next call re-polls.
    import time as _time

    _time.sleep(0.01)
    assert reader.current_wasting_strategy() == "aggressive"
