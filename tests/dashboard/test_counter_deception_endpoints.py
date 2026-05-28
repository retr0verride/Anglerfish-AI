"""Stage 12 slice 12.4: dashboard counter-deception routes + alerts."""

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


@pytest.fixture
def authed_client(
    settings: AnglerfishSettings,
    tmp_path: Path,
) -> Iterator[tuple[TestClient, Path]]:
    audit_path = tmp_path / "audit.jsonl"
    audit = AuditLog(audit_path)
    app = create_app(_settings_with_auth(settings), audit=audit)
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
# Pin CRUD
# ---------------------------------------------------------------------------


def test_pin_requires_auth(settings: AnglerfishSettings) -> None:
    app = create_app(_settings_with_auth(settings))
    with TestClient(app) as c:
        r = c.post(
            "/api/counter_deception/pin",
            json={"source_ip": "203.0.113.7", "mode": "both"},
        )
    assert r.status_code in (401, 403)


def test_pin_persists_and_audits(authed_client: tuple[TestClient, Path]) -> None:
    client, audit_path = authed_client
    r = client.post(
        "/api/counter_deception/pin",
        json={"source_ip": "203.0.113.7", "mode": "both"},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["source_ip"] == "203.0.113.7"
    assert body["mode"] == "both"
    assert body["created_by"] == _TEST_USERNAME
    text = audit_path.read_text(encoding="utf-8")
    assert '"event_type":"dashboard.counter_deception_pinned"' in text
    assert '"mode":"both"' in text


def test_pin_rejects_invalid_mode(authed_client: tuple[TestClient, Path]) -> None:
    client, _ = authed_client
    r = client.post(
        "/api/counter_deception/pin",
        json={"source_ip": "203.0.113.7", "mode": "aggressive"},
    )
    assert r.status_code == 422


def test_pin_off_is_accepted_as_whitelist(authed_client: tuple[TestClient, Path]) -> None:
    client, _ = authed_client
    r = client.post(
        "/api/counter_deception/pin",
        json={"source_ip": "198.51.100.9", "mode": "off"},
    )
    assert r.status_code == 200
    assert r.json()["mode"] == "off"


def test_pin_list_and_overwrite(authed_client: tuple[TestClient, Path]) -> None:
    client, _ = authed_client
    client.post(
        "/api/counter_deception/pin",
        json={"source_ip": "203.0.113.7", "mode": "garble"},
    )
    r = client.post(
        "/api/counter_deception/pin",
        json={"source_ip": "203.0.113.7", "mode": "timebomb"},
    )
    assert r.json()["mode"] == "timebomb"
    listing = client.get("/api/counter_deception/pin").json()
    assert listing["count"] == 1
    assert listing["items"][0]["mode"] == "timebomb"


def test_delete_pin_and_audit(authed_client: tuple[TestClient, Path]) -> None:
    client, audit_path = authed_client
    client.post(
        "/api/counter_deception/pin",
        json={"source_ip": "203.0.113.7", "mode": "both"},
    )
    r = client.request("DELETE", "/api/counter_deception/pin/203.0.113.7")
    assert r.status_code == 200, r.text
    assert r.json()["deleted"] is True
    assert client.get("/api/counter_deception/pin").json()["count"] == 0
    assert '"event_type":"dashboard.counter_deception_unpinned"' in audit_path.read_text(
        encoding="utf-8",
    )


def test_delete_missing_pin_404(authed_client: tuple[TestClient, Path]) -> None:
    client, _ = authed_client
    r = client.request("DELETE", "/api/counter_deception/pin/8.8.8.8")
    assert r.status_code == 404


# ---------------------------------------------------------------------------
# State + engagements
# ---------------------------------------------------------------------------


def test_state_returns_config_snapshot(authed_client: tuple[TestClient, Path]) -> None:
    client, _ = authed_client
    r = client.get("/api/counter_deception/state")
    assert r.status_code == 200, r.text
    body = r.json()
    cfg = body["config"]
    # Defaults from AnglerfishSettings.counter_deception (disabled by default).
    assert cfg["enabled"] is False
    assert cfg["mode"] == "both"
    assert cfg["engagement_threshold"] == 70
    assert "/root/.ssh/id_rsa" in cfg["garble_paths"]
    assert cfg["timebomb_cold_to_mild"] == 6
    assert cfg["timebomb_mild_to_severe"] == 16
    assert body["active_pins"] == 0


def test_state_counts_active_pins(authed_client: tuple[TestClient, Path]) -> None:
    client, _ = authed_client
    client.post(
        "/api/counter_deception/pin",
        json={"source_ip": "203.0.113.7", "mode": "both"},
    )
    assert client.get("/api/counter_deception/state").json()["active_pins"] == 1


def test_engagements_reads_audit_log(authed_client: tuple[TestClient, Path]) -> None:
    client, audit_path = authed_client
    # Seed a bridge.counter_deception_engaged event the way the bridge would.
    AuditLog(audit_path).record(
        "bridge.counter_deception_engaged",
        session_id="11111111-1111-1111-1111-111111111111",
        attacker_ip="203.0.113.7",
        mode="both",
        trigger="threat",
        garble_paths_count=2,
        timebomb_thresholds=[6, 16],
        threat_score=82,
    )
    r = client.get("/api/counter_deception/engagements")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["count"] == 1
    item = body["items"][0]
    assert item["attacker_ip"] == "203.0.113.7"
    assert item["mode"] == "both"
    assert item["trigger"] == "threat"
    assert item["threat_score"] == 82


def test_engagements_rejects_bad_since(authed_client: tuple[TestClient, Path]) -> None:
    client, _ = authed_client
    r = client.get("/api/counter_deception/engagements", params={"since": "not-a-date"})
    assert r.status_code == 400


# ---------------------------------------------------------------------------
# Alerts panel
# ---------------------------------------------------------------------------


def test_alerts_surfaces_counter_deception_engaged(
    authed_client: tuple[TestClient, Path],
) -> None:
    client, audit_path = authed_client
    AuditLog(audit_path).record(
        "bridge.counter_deception_engaged",
        session_id="11111111-1111-1111-1111-111111111111",
        attacker_ip="203.0.113.7",
        mode="garble",
        trigger="pin",
        garble_paths_count=2,
        timebomb_thresholds=[0, 0],
        threat_score=None,
    )
    r = client.get("/api/alerts", params={"kind": "counter_deception_engaged"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert len(body["items"]) >= 1
    item = body["items"][0]
    assert item["kind"] == "counter_deception_engaged"
    assert item["source_ip"] == "203.0.113.7"
    assert "garble via pin on 203.0.113.7" in item["detail"]
