"""Tests for the Stage 7 slice 4 dashboard surfaces.

GET /api/sessions/{id}/intent + GET /api/export/intents + the
alerts panel's intent_summary kind.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient

from anglerfish.audit import AuditLog
from anglerfish.config import AnglerfishSettings
from anglerfish.dashboard import create_app
from anglerfish.dashboard.alerts import ALERT_KINDS
from anglerfish.dashboard.state import DashboardState
from anglerfish.models import (
    CommandTurn,
    IntentSummary,
    ResponseSource,
    SessionSnapshot,
)


@pytest.fixture
def audit_path(tmp_path: Path) -> Path:
    return tmp_path / "audit.jsonl"


@pytest.fixture
def client(
    settings: AnglerfishSettings,
    audit_path: Path,
    dashboard_state: DashboardState,
) -> Iterator[TestClient]:
    audit = AuditLog(audit_path)
    app = create_app(settings, state=dashboard_state, audit=audit)
    with TestClient(app) as c:
        yield c


def _snapshot() -> SessionSnapshot:
    now = datetime(2026, 5, 25, 12, 0, tzinfo=UTC)
    return SessionSnapshot(
        session_id=uuid4(),
        source_ip="203.0.113.7",
        username="root",
        fake_hostname="srv-prod-01",
        fake_username="root",
        fake_cwd="/root",
        started_at=now,
        last_activity_at=now,
        turns=(
            CommandTurn(
                command="ls",
                response="",
                source=ResponseSource.AI,
                timestamp=now,
                latency_ms=1.0,
            ),
        ),
    )


def _intent(*, session_id: UUID, extracted_at: datetime) -> IntentSummary:
    return IntentSummary(
        session_id=session_id,
        actor_profile="automated",
        intent="Deploy cryptominer.",
        why="Downloaded miner; configured pool URL.",
        matched_techniques=("T1059.004", "T1496"),
        confidence="high",
        summary="Automated session.",
        extracted_at=extracted_at,
    )


# ---------------------------------------------------------------------------
# Per-session intent route
# ---------------------------------------------------------------------------


async def test_get_session_intent_returns_404_when_no_summary(
    client: TestClient,
    dashboard_state: DashboardState,
) -> None:
    snap = _snapshot()
    await dashboard_state.update_session(snap)
    r = client.get(f"/api/sessions/{snap.session_id}/intent")
    assert r.status_code == 404


async def test_get_session_intent_returns_payload_when_persisted(
    client: TestClient,
    dashboard_state: DashboardState,
) -> None:
    snap = _snapshot()
    await dashboard_state.update_session(snap)
    intent = _intent(
        session_id=snap.session_id,
        extracted_at=datetime(2026, 5, 25, 12, 30, tzinfo=UTC),
    )
    await dashboard_state.upsert_intent(intent)
    r = client.get(f"/api/sessions/{snap.session_id}/intent")
    assert r.status_code == 200
    body = r.json()
    assert body["session_id"] == str(snap.session_id)
    assert body["actor_profile"] == "automated"
    assert body["confidence"] == "high"
    assert body["matched_techniques"] == ["T1059.004", "T1496"]


def test_get_session_intent_404_for_unknown_session_id(
    client: TestClient,
) -> None:
    r = client.get(f"/api/sessions/{uuid4()}/intent")
    assert r.status_code == 404


# ---------------------------------------------------------------------------
# Alerts panel: intent_summary kind is live (no longer stubbed)
# ---------------------------------------------------------------------------


def test_alerts_intent_summary_kind_is_recognized() -> None:
    assert "intent_summary" in ALERT_KINDS


def test_alerts_filter_by_intent_summary_returns_recent_events(
    client: TestClient,
    audit_path: Path,
) -> None:
    now = datetime.now(tz=UTC)
    sid = uuid4()
    ts = (now - timedelta(seconds=30)).isoformat()
    audit_path.write_text(
        '{"ts":"' + ts + '","event_type":"bridge.intent_extracted",'
        '"session_id":"' + str(sid) + '","actor_profile":"automated",'
        '"confidence":"high","intent":"x","why":"x",'
        '"matched_techniques":[],"summary":"x","extracted_at":"' + ts + '"}\n',
        encoding="utf-8",
    )
    body = client.get("/api/alerts?kind=intent_summary").json()
    assert len(body["items"]) == 1
    assert body["items"][0]["kind"] == "intent_summary"


# ---------------------------------------------------------------------------
# GET /api/export/intents
# ---------------------------------------------------------------------------


def test_export_intents_empty_default_window(client: TestClient) -> None:
    body = client.get("/api/export/intents").json()
    assert body["available"] is True
    assert body["format"] == "json"
    assert body["count"] == 0
    assert body["items"] == []


async def test_export_intents_returns_in_range(
    client: TestClient,
    dashboard_state: DashboardState,
) -> None:
    now = datetime.now(tz=UTC)
    snap1, snap2 = _snapshot(), _snapshot()
    await dashboard_state.update_session(snap1)
    await dashboard_state.update_session(snap2)
    in_window = _intent(
        session_id=snap1.session_id,
        extracted_at=now - timedelta(hours=1),
    )
    out_of_window = _intent(
        session_id=snap2.session_id,
        extracted_at=now - timedelta(days=3),
    )
    await dashboard_state.upsert_intent(in_window)
    await dashboard_state.upsert_intent(out_of_window)

    body = client.get("/api/export/intents").json()
    # Default 24-hour window keeps only the recent one.
    assert body["count"] == 1
    assert body["items"][0]["session_id"] == str(snap1.session_id)


def test_export_intents_rejects_inverted_range(client: TestClient) -> None:
    r = client.get(
        "/api/export/intents?from=2026-05-25T12:00:00Z&to=2026-05-25T11:00:00Z",
    )
    assert r.status_code == 400


def test_export_intents_emits_dashboard_export_served(
    client: TestClient,
    audit_path: Path,
) -> None:
    client.get("/api/export/intents")
    text = audit_path.read_text(encoding="utf-8") if audit_path.exists() else ""
    assert '"event_type":"dashboard.export_served"' in text
    assert '"kind":"intents"' in text
