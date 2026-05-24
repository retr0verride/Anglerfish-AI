"""Tests for the Stage 3 system-health endpoints."""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from anglerfish.audit import AuditLog
from anglerfish.config import AnglerfishSettings
from anglerfish.dashboard import create_app


@pytest.fixture
def audit_path(tmp_path: Path) -> Path:
    return tmp_path / "audit.jsonl"


@pytest.fixture
def client(
    settings: AnglerfishSettings,
    audit_path: Path,
) -> Iterator[TestClient]:
    audit = AuditLog(audit_path)
    app = create_app(settings, audit=audit)
    with TestClient(app) as c:
        yield c


# ---------------------------------------------------------------------------
# /api/health/ollama
# ---------------------------------------------------------------------------


def test_ollama_endpoint_returns_unreachable_when_no_server(
    client: TestClient,
) -> None:
    # The test fixture uses default Ollama URL (127.0.0.1:11434).
    # Nothing is listening; reachable=False, no 500.
    r = client.get("/api/health/ollama")
    assert r.status_code == 200
    body = r.json()
    assert body["reachable"] is False
    assert body["model"] == "qwen3:14b"
    assert body["integrity_check"]["status"] == "unknown"


def test_ollama_endpoint_surfaces_recent_integrity_pass(
    client: TestClient,
    audit_path: Path,
) -> None:
    audit_path.write_text(
        '{"ts":"2026-05-24T12:00:00+00:00","event_type":"bridge.model_integrity_verified","model":"qwen3:14b"}\n',
        encoding="utf-8",
    )
    body = client.get("/api/health/ollama").json()
    assert body["integrity_check"]["status"] == "passed"
    assert body["integrity_check"]["expected_hash_present"] is True


def test_ollama_endpoint_surfaces_recent_integrity_skip(
    client: TestClient,
    audit_path: Path,
) -> None:
    audit_path.write_text(
        '{"ts":"2026-05-24T12:00:00+00:00","event_type":"bridge.model_integrity_skipped"}\n',
        encoding="utf-8",
    )
    body = client.get("/api/health/ollama").json()
    assert body["integrity_check"]["status"] == "skipped"
    assert body["integrity_check"]["expected_hash_present"] is False


# ---------------------------------------------------------------------------
# /api/health/forwarder
# ---------------------------------------------------------------------------


def test_forwarder_endpoint_reports_unknown_when_no_events(
    client: TestClient,
) -> None:
    body = client.get("/api/health/forwarder").json()
    assert body["splunk_enabled"] is False
    assert body["last_delivery_status"] == "unknown"
    assert body["last_delivery_at"] is None
    # Fallback file doesn't exist -> 0 bytes (not 500).
    assert body["fallback_queue_depth_bytes"] == 0


def test_forwarder_endpoint_reports_recent_success(
    client: TestClient,
    audit_path: Path,
) -> None:
    audit_path.write_text(
        '{"ts":"2026-05-24T12:00:00+00:00","event_type":"forwarder.hec_delivered"}\n',
        encoding="utf-8",
    )
    body = client.get("/api/health/forwarder").json()
    assert body["last_delivery_status"] == "success"
    assert body["last_delivery_at"] == "2026-05-24T12:00:00+00:00"


def test_forwarder_endpoint_picks_latest_event_only(
    client: TestClient,
    audit_path: Path,
) -> None:
    audit_path.write_text(
        '{"ts":"2026-05-24T11:00:00+00:00","event_type":"forwarder.hec_delivered"}\n'
        '{"ts":"2026-05-24T12:00:00+00:00","event_type":"forwarder.hec_failed"}\n',
        encoding="utf-8",
    )
    body = client.get("/api/health/forwarder").json()
    assert body["last_delivery_status"] == "failed"


# ---------------------------------------------------------------------------
# /api/health/sessions
# ---------------------------------------------------------------------------


def test_sessions_endpoint_reports_zero_when_empty(client: TestClient) -> None:
    body = client.get("/api/health/sessions").json()
    assert body["active_sessions"] == 0
    assert body["max_concurrent_requests"] == 8  # default
    assert body["utilisation_pct"] == 0.0
    assert body["tokens_per_minute"]["window_minutes"] == 5
    assert body["tokens_per_minute"]["rate"] == 0.0


def test_sessions_endpoint_counts_recent_command_events(
    client: TestClient,
    audit_path: Path,
) -> None:
    # Five command events in the last minute. Window is 5 min so rate
    # is 5 / 5 = 1.0 per minute.
    now = datetime.now(tz=UTC)
    lines = []
    for i in range(5):
        ts = (now - timedelta(seconds=i * 10)).isoformat()
        lines.append(
            f'{{"ts":"{ts}","event_type":"bridge.command_bridge"}}\n',
        )
    audit_path.write_text("".join(lines), encoding="utf-8")
    body = client.get("/api/health/sessions").json()
    assert body["tokens_per_minute"]["rate"] == 1.0


def test_sessions_endpoint_ignores_old_events(
    client: TestClient,
    audit_path: Path,
) -> None:
    long_ago = (datetime.now(tz=UTC) - timedelta(hours=1)).isoformat()
    audit_path.write_text(
        f'{{"ts":"{long_ago}","event_type":"bridge.command_bridge"}}\n',
        encoding="utf-8",
    )
    body = client.get("/api/health/sessions").json()
    assert body["tokens_per_minute"]["rate"] == 0.0


# ---------------------------------------------------------------------------
# Health endpoints are *all* gated behind require_auth (the unauthenticated
# /api/health endpoint stays as the liveness probe and is not affected).
# ---------------------------------------------------------------------------


def test_unauthenticated_health_alias_still_open(client: TestClient) -> None:
    # Open-mode fixture has no admin password; require_auth is a no-op
    # here, so this confirms the liveness probe is reachable and the
    # specific health-panel endpoints are reachable too. The auth-gating
    # test lives in test_settings_endpoints.py where the auth flow is
    # exercised end-to-end.
    assert client.get("/api/health").status_code == 200
    assert client.get("/api/health/ollama").status_code == 200
    assert client.get("/api/health/forwarder").status_code == 200
    assert client.get("/api/health/sessions").status_code == 200
