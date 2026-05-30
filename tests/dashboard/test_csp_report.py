"""CSP violation report endpoint: auth gate, audit record, input bounds."""

from __future__ import annotations

import json
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

_REPORT = {
    "csp-report": {
        "document-uri": "http://127.0.0.1:8420/",
        "violated-directive": "script-src 'self'",
        "blocked-uri": "inline",
        "source-file": "http://127.0.0.1:8420/static/app.js",
        "line-number": 42,
    }
}


def _settings_with_auth(base: AnglerfishSettings) -> AnglerfishSettings:
    return base.model_copy(
        update={
            "dashboard": DashboardConfig(
                session_secret=base.dashboard.session_secret,
                admin_username=_TEST_USERNAME,
                admin_password_hash=SecretStr(hash_password(_TEST_PASSWORD)),
            ),
        },
    )


@pytest.fixture
def authed_client(
    settings: AnglerfishSettings,
    tmp_path: Path,
) -> Iterator[tuple[TestClient, Path]]:
    audit_path = tmp_path / "audit.jsonl"
    app = create_app(_settings_with_auth(settings), audit=AuditLog(audit_path))
    with TestClient(app) as client:
        login = client.post(
            "/api/login",
            json={"username": _TEST_USERNAME, "password": _TEST_PASSWORD},
        )
        assert login.status_code == 200, login.text
        yield client, audit_path


def test_report_requires_auth(settings: AnglerfishSettings) -> None:
    # The browser sends the report without CSRF, so the endpoint is auth
    # only; in password mode an unauthenticated POST is rejected.
    app = create_app(_settings_with_auth(settings))
    with TestClient(app) as client:
        r = client.post("/api/csp-report", json=_REPORT)
    assert r.status_code in (401, 403)


def test_valid_report_is_audited(authed_client: tuple[TestClient, Path]) -> None:
    client, audit_path = authed_client
    r = client.post("/api/csp-report", json=_REPORT)
    assert r.status_code == 204
    assert r.content == b""

    line = audit_path.read_text(encoding="utf-8").strip().splitlines()[-1]
    event = json.loads(line)
    assert event["event_type"] == "dashboard.csp_violation"
    assert event["violated_directive"] == "script-src 'self'"
    assert event["blocked_uri"] == "inline"
    assert event["operator"] == _TEST_USERNAME


def test_effective_directive_is_used_when_violated_absent(
    authed_client: tuple[TestClient, Path],
) -> None:
    client, audit_path = authed_client
    report = {"csp-report": {"effective-directive": "img-src", "blocked-uri": "x"}}
    assert client.post("/api/csp-report", json=report).status_code == 204
    event = json.loads(audit_path.read_text(encoding="utf-8").strip().splitlines()[-1])
    assert event["violated_directive"] == "img-src"


def test_oversized_body_rejected(authed_client: tuple[TestClient, Path]) -> None:
    client, _ = authed_client
    bloat = {"csp-report": {"blocked-uri": "x" * 9000}}
    assert client.post("/api/csp-report", json=bloat).status_code == 413


def test_malformed_body_rejected(authed_client: tuple[TestClient, Path]) -> None:
    client, _ = authed_client
    assert client.post("/api/csp-report", content=b"not json").status_code == 400
    # Valid JSON but no csp-report envelope.
    assert client.post("/api/csp-report", json={"nope": 1}).status_code == 400


def test_recorded_fields_are_truncated(authed_client: tuple[TestClient, Path]) -> None:
    client, audit_path = authed_client
    # Under the 8 KB body cap but over the 512-char per-field cap.
    report = {"csp-report": {"violated-directive": "d", "blocked-uri": "u" * 2000}}
    assert client.post("/api/csp-report", json=report).status_code == 204
    event = json.loads(audit_path.read_text(encoding="utf-8").strip().splitlines()[-1])
    assert len(event["blocked_uri"]) == 512
