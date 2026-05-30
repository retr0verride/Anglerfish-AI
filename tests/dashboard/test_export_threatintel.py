"""Stage 13 slice 13.4: STIX/MISP export endpoints + stub flip."""

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
from anglerfish.honeytokens.schema import Honeytoken
from anglerfish.models import CommandTurn, ResponseSource, SessionSnapshot
from anglerfish.models.intent import IntentSummary

_AT = datetime(2026, 5, 29, 12, 0, tzinfo=UTC)
_RANGE = {"from": "2026-05-28T00:00:00", "to": "2026-05-30T00:00:00"}


@pytest.fixture
def client(
    settings: AnglerfishSettings,
    tmp_path: Path,
    dashboard_state: DashboardState,
) -> Iterator[tuple[TestClient, DashboardState, Path]]:
    audit_path = tmp_path / "audit.jsonl"
    app = create_app(settings, state=dashboard_state, audit=AuditLog(audit_path))
    with TestClient(app) as c:
        yield c, dashboard_state, audit_path


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
                command="ls",
                response="",
                source=ResponseSource.AI,
                timestamp=_AT,
                latency_ms=1.0,
            ),
        ),
    )
    await state.update_session(snap)
    await state.upsert_intent(
        IntentSummary(
            session_id=snap.session_id,
            actor_profile="opportunistic",
            intent="cryptojacking",
            why="deployed a miner",
            matched_techniques=("T1496",),
            confidence="high",
            summary="Cryptojacking.",
            extracted_at=_AT,
        ),
    )
    await state.register_honeytoken(
        Honeytoken(
            id="MFRGGZDFMZTWQ2LK",
            kind="aws",
            payload="SECRETPAYLOAD",
            callback_url="https://cb.example/h1",
            placed_at="/root/.aws/credentials",
            source_ip="203.0.113.7",
            session_id=snap.session_id,
            created_at=_AT,
        ),
    )
    return snap


async def test_export_stix_endpoint(
    client: tuple[TestClient, DashboardState, Path],
) -> None:
    c, state, _ = client
    await _seed(state)
    r = c.get("/api/export/stix", params=_RANGE)
    assert r.status_code == 200, r.text
    bundle = r.json()
    assert bundle["type"] == "bundle"
    types = {o["type"] for o in bundle["objects"]}
    assert {"identity", "observed-data", "ipv4-addr", "indicator", "note"} <= types
    assert "SECRETPAYLOAD" not in r.text


async def test_export_misp_endpoint_and_audit(
    client: tuple[TestClient, DashboardState, Path],
) -> None:
    c, state, audit_path = client
    await _seed(state)
    r = c.get("/api/export/misp", params=_RANGE)
    assert r.status_code == 200, r.text
    event = r.json()["Event"]
    assert any(a["type"] == "ip-src" for a in event["Attribute"])
    text = audit_path.read_text(encoding="utf-8")
    assert '"event_type":"dashboard.export_served"' in text
    assert '"export_format":"misp_json"' in text


def test_export_stubs_report_threatintel_available(
    client: tuple[TestClient, DashboardState, Path],
) -> None:
    c, _, _ = client
    r = c.get("/api/export/sessions", params=_RANGE)
    assert r.status_code == 200, r.text
    stubs = r.json()["stubs"]
    assert stubs["stix2"]["available"] is True
    assert stubs["misp_json"]["available"] is True


def test_export_stix_rejects_oversize_range(
    client: tuple[TestClient, DashboardState, Path],
) -> None:
    c, _, _ = client
    r = c.get(
        "/api/export/stix", params={"from": "2026-01-01T00:00:00", "to": "2026-05-01T00:00:00"}
    )
    assert r.status_code == 400
