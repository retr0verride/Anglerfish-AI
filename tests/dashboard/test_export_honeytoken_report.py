"""Stage 13 slice 13.3: honeytoken_report CSV export endpoint + stub flip."""

from __future__ import annotations

import csv
import io
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

_AT = datetime(2026, 5, 29, 12, 0, tzinfo=UTC)
_TOKEN_ID = "MFRGGZDFMZTWQ2LK"


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


async def _register(state: DashboardState, token_id: str = _TOKEN_ID) -> None:
    await state.register_honeytoken(
        Honeytoken(
            id=token_id,
            kind="aws",
            payload="SECRETPAYLOAD",
            callback_url="https://cb.example/h1",
            placed_at="/root/.aws/credentials",
            source_ip="203.0.113.7",
            session_id=uuid4(),
            created_at=_AT,
        ),
    )


def _csv_rows(body: str) -> list[dict[str, str]]:
    return list(csv.DictReader(io.StringIO(body)))


async def test_report_is_csv_with_payload(
    client: tuple[TestClient, DashboardState, AuditLog],
) -> None:
    c, state, _ = client
    await _register(state)
    r = c.get("/api/export/honeytoken_report")
    assert r.status_code == 200, r.text
    assert r.headers["content-type"].startswith("text/csv")
    assert "attachment" in r.headers["content-disposition"]
    rows = _csv_rows(r.text)
    assert len(rows) == 1
    # Operator-only report: the secret payload IS present here (unlike STIX/MISP).
    assert rows[0]["id"] == _TOKEN_ID
    assert rows[0]["payload"] == "SECRETPAYLOAD"
    assert rows[0]["fired"] == "false"


async def test_report_joins_callback_events(
    client: tuple[TestClient, DashboardState, AuditLog],
) -> None:
    c, state, audit = client
    await _register(state)
    audit.record(
        "bridge.honeytoken_callback",
        token_id=_TOKEN_ID,
        callback_source_ip="198.51.100.9",
    )
    r = c.get("/api/export/honeytoken_report")
    assert r.status_code == 200, r.text
    row = _csv_rows(r.text)[0]
    assert row["fired"] == "true"
    assert row["callback_count"] == "1"
    assert row["last_callback_source_ip"] == "198.51.100.9"


async def test_report_audits_export_served(
    client: tuple[TestClient, DashboardState, AuditLog],
) -> None:
    c, state, audit = client
    await _register(state)
    c.get("/api/export/honeytoken_report")
    text = audit.path.read_text(encoding="utf-8")
    assert '"event_type":"dashboard.export_served"' in text
    assert '"export_format":"honeytoken_report"' in text


def test_stub_reports_honeytoken_report_available(
    client: tuple[TestClient, DashboardState, AuditLog],
) -> None:
    c, _, _ = client
    r = c.get(
        "/api/export/sessions", params={"from": "2026-05-28T00:00:00", "to": "2026-05-30T00:00:00"}
    )
    assert r.status_code == 200, r.text
    assert r.json()["stubs"]["honeytoken_report"]["available"] is True
