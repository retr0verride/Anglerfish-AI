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
    models_by_role = {m["role"]: m for m in body["models"]}
    assert models_by_role["fast"]["model"] == "qwen3:14b"
    assert models_by_role["deep"]["model"] == "phi-4"
    assert models_by_role["fast"]["warmed_at"] is None
    assert body["integrity_check"]["status"] == "unknown"


def test_ollama_endpoint_surfaces_recent_warmup_per_role(
    client: TestClient,
    audit_path: Path,
) -> None:
    audit_path.write_text(
        '{"ts":"2026-05-25T10:00:00+00:00","event_type":"llm.warmup_succeeded","role":"fast","model":"qwen3:14b"}\n'
        '{"ts":"2026-05-25T10:00:01+00:00","event_type":"llm.warmup_failed","role":"deep","model":"phi-4","error":"x"}\n',
        encoding="utf-8",
    )
    body = client.get("/api/health/ollama").json()
    models_by_role = {m["role"]: m for m in body["models"]}
    assert models_by_role["fast"]["warmed_at"] == "2026-05-25T10:00:00+00:00"
    assert models_by_role["fast"]["last_warmup_status"] == "succeeded"
    assert models_by_role["deep"]["warmed_at"] == "2026-05-25T10:00:01+00:00"
    assert models_by_role["deep"]["last_warmup_status"] == "failed"


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


# /api/health/forwarder was removed in 2026-05 alongside the
# Cowrie integration; the forwarder package itself is gone.

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
    assert client.get("/api/health/sessions").status_code == 200


# ---------------------------------------------------------------------------
# Stage 6 slice 5: /api/health/sessions includes a wasting block
# ---------------------------------------------------------------------------


def test_sessions_endpoint_wasting_block_defaults_when_empty(
    client: TestClient,
) -> None:
    body = client.get("/api/health/sessions").json()
    wasting = body["wasting"]
    assert wasting["strategy"] == "off"  # default BridgeConfig
    assert wasting["avg_wasted_ms_per_session"] == 0
    assert wasting["sessions_at_budget_cap"] == 0


def test_sessions_endpoint_wasting_aggregates_recent_events(
    client: TestClient,
    audit_path: Path,
) -> None:
    now = datetime.now(tz=UTC)
    ts = (now - timedelta(seconds=30)).isoformat()
    sid_a = "11111111-1111-1111-1111-111111111111"
    sid_b = "22222222-2222-2222-2222-222222222222"
    lines = [
        # two wasting applications against session A: 1000 + 2000 ms.
        '{"ts":"' + ts + '","event_type":"bridge.wasting_applied",'
        '"session_id":"' + sid_a + '","strategy":"light","wasted_ms":1000,'
        '"pre_message":false,"clarification_injected":false}',
        '{"ts":"' + ts + '","event_type":"bridge.wasting_applied",'
        '"session_id":"' + sid_a + '","strategy":"light","wasted_ms":2000,'
        '"pre_message":false,"clarification_injected":false}',
        # one against session B: 4000 ms; B then hits the cap.
        '{"ts":"' + ts + '","event_type":"bridge.wasting_applied",'
        '"session_id":"' + sid_b + '","strategy":"aggressive","wasted_ms":4000,'
        '"pre_message":true,"clarification_injected":false}',
        '{"ts":"' + ts + '","event_type":"bridge.wasting_budget_exhausted",'
        '"session_id":"' + sid_b + '","wasted_ms":4000,"cap_ms":3000}',
    ]
    audit_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    body = client.get("/api/health/sessions").json()
    wasting = body["wasting"]
    # 1000 + 2000 + 4000 = 7000 across 2 distinct sessions = 3500 avg.
    assert wasting["avg_wasted_ms_per_session"] == 3500
    # Session B is still capped (no lure.session_closed seen).
    assert wasting["sessions_at_budget_cap"] == 1


def test_sessions_endpoint_wasting_drops_closed_capped_sessions(
    client: TestClient,
    audit_path: Path,
) -> None:
    now = datetime.now(tz=UTC)
    ts = (now - timedelta(seconds=30)).isoformat()
    sid = "33333333-3333-3333-3333-333333333333"
    lines = [
        '{"ts":"' + ts + '","event_type":"bridge.wasting_budget_exhausted",'
        '"session_id":"' + sid + '","wasted_ms":4000,"cap_ms":3000}',
        '{"ts":"' + ts + '","event_type":"lure.session_closed","session_id":"' + sid + '"}',
    ]
    audit_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    body = client.get("/api/health/sessions").json()
    # The session hit the cap then closed; no longer counted as
    # "currently at cap".
    assert body["wasting"]["sessions_at_budget_cap"] == 0
