"""Stage 13 slice 13.4: per-session PDF export endpoint + stub flip."""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from anglerfish.audit import AuditLog
from anglerfish.config import AnglerfishSettings
from anglerfish.dashboard import create_app
from anglerfish.dashboard.state import DashboardState
from anglerfish.models import CommandTurn, ResponseSource, SessionSnapshot

_AT = datetime(2026, 5, 29, 12, 0, tzinfo=UTC)


@pytest.fixture
def client(
    settings: AnglerfishSettings,
    tmp_path: Path,
    dashboard_state: DashboardState,
) -> Iterator[tuple[TestClient, DashboardState, AuditLog]]:
    audit = AuditLog(tmp_path / "audit.jsonl")
    app = create_app(settings, state=dashboard_state, audit=audit)
    with TestClient(app) as c:
        yield c, dashboard_state, audit


async def _seed(state: DashboardState) -> SessionSnapshot:
    snap = SessionSnapshot(
        session_id=uuid4(),
        source_ip="203.0.113.7",
        username="root",
        fake_hostname="srv",
        fake_username="root",
        fake_cwd="/root",
        started_at=_AT,
        last_activity_at=_AT,
        turns=(
            CommandTurn(
                command="whoami",
                response="root",
                source=ResponseSource.AI,
                timestamp=_AT,
                latency_ms=1.0,
            ),
        ),
    )
    await state.update_session(snap)
    return snap


async def test_report_returns_pdf(
    client: tuple[TestClient, DashboardState, AuditLog],
) -> None:
    c, state, _ = client
    snap = await _seed(state)
    r = c.get("/api/export/report", params={"session_id": str(snap.session_id)})
    assert r.status_code == 200, r.text
    assert r.headers["content-type"] == "application/pdf"
    assert "attachment" in r.headers["content-disposition"]
    assert r.content[:4] == b"%PDF"


async def test_report_audits_export_served(
    client: tuple[TestClient, DashboardState, AuditLog],
) -> None:
    c, state, audit = client
    snap = await _seed(state)
    c.get("/api/export/report", params={"session_id": str(snap.session_id)})
    text = audit.path.read_text(encoding="utf-8")
    assert '"event_type":"dashboard.export_served"' in text
    assert '"export_format":"report_pdf"' in text


def test_report_unknown_session_404(
    client: tuple[TestClient, DashboardState, AuditLog],
) -> None:
    c, _, _ = client
    r = c.get("/api/export/report", params={"session_id": str(uuid4())})
    assert r.status_code == 404


def test_report_requires_session_id(
    client: tuple[TestClient, DashboardState, AuditLog],
) -> None:
    c, _, _ = client
    r = c.get("/api/export/report")
    assert r.status_code == 422  # missing required query param


def test_stub_reports_report_pdf_available(
    client: tuple[TestClient, DashboardState, AuditLog],
) -> None:
    c, _, _ = client
    r = c.get(
        "/api/export/sessions",
        params={"from": "2026-05-28T00:00:00", "to": "2026-05-30T00:00:00"},
    )
    assert r.status_code == 200, r.text
    assert r.json()["stubs"]["report_pdf"]["available"] is True
