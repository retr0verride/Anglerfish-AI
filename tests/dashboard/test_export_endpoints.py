"""Tests for the Stage 3 export endpoints."""

from __future__ import annotations

import json
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from anglerfish.audit import AuditLog
from anglerfish.config import AnglerfishSettings
from anglerfish.dashboard import DashboardState, create_app
from anglerfish.dashboard.export import (
    MAX_EXPORT_WINDOW_DAYS,
    ExportRangeError,
    parse_range,
)
from anglerfish.models.session import CommandTurn, ResponseSource, SessionSnapshot


def _snapshot(*, started: datetime) -> SessionSnapshot:
    return SessionSnapshot(
        session_id=uuid4(),
        source_ip="203.0.113.7",
        username="root",
        fake_hostname="srv-prod-01",
        fake_username="root",
        fake_cwd="/root",
        started_at=started,
        last_activity_at=started,
        turns=(
            CommandTurn(
                command="ls",
                response="",
                source=ResponseSource.AI,
                timestamp=started,
                latency_ms=1.0,
            ),
        ),
    )


@pytest.fixture
def audit_path(tmp_path: Path) -> Path:
    return tmp_path / "audit.jsonl"


@pytest.fixture
def state(dashboard_state: DashboardState) -> DashboardState:
    return dashboard_state


@pytest.fixture
def client(
    settings: AnglerfishSettings,
    state: DashboardState,
    audit_path: Path,
) -> Iterator[TestClient]:
    app = create_app(settings, state=state, audit=AuditLog(audit_path))
    with TestClient(app) as c:
        yield c


# ---------------------------------------------------------------------------
# parse_range unit tests
# ---------------------------------------------------------------------------


def test_parse_range_defaults_to_last_24_hours() -> None:
    now = datetime(2026, 5, 24, 12, 0, tzinfo=UTC)
    start, end = parse_range(from_=None, to_=None, now=now)
    assert end == now
    assert (end - start) == timedelta(hours=24)


def test_parse_range_rejects_inverted_range() -> None:
    with pytest.raises(ExportRangeError, match=">= 'from'"):
        parse_range(from_="2026-05-24T12:00:00Z", to_="2026-05-24T11:00:00Z")


def test_parse_range_rejects_span_over_cap() -> None:
    with pytest.raises(ExportRangeError, match="cap"):
        parse_range(
            from_="2026-05-01T00:00:00Z",
            to_="2026-05-15T00:00:00Z",  # 14 days
        )


def test_parse_range_accepts_exactly_cap() -> None:
    start, end = parse_range(
        from_="2026-05-01T00:00:00Z",
        to_=f"2026-05-0{MAX_EXPORT_WINDOW_DAYS + 1}T00:00:00Z",
    )
    assert (end - start).days == MAX_EXPORT_WINDOW_DAYS


def test_parse_range_rejects_malformed_iso() -> None:
    with pytest.raises(ExportRangeError, match="invalid ISO"):
        parse_range(from_="not-a-date", to_=None)


def test_parse_range_treats_naive_as_utc() -> None:
    start, _ = parse_range(from_="2026-05-24T12:00:00", to_="2026-05-24T13:00:00")
    assert start.tzinfo is UTC


# ---------------------------------------------------------------------------
# /api/export/sessions (JSON)
# ---------------------------------------------------------------------------


async def _seed_state(state: DashboardState, snap: SessionSnapshot) -> None:
    await state.update_session(snap)


def test_session_export_json_returns_in_range_sessions(
    client: TestClient,
    state: DashboardState,
) -> None:
    now = datetime.now(tz=UTC)
    portal = client.portal
    assert portal is not None
    portal.call(_seed_state, state, _snapshot(started=now - timedelta(hours=1)))
    portal.call(_seed_state, state, _snapshot(started=now - timedelta(days=3)))
    r = client.get("/api/export/sessions")
    assert r.status_code == 200
    body = r.json()
    assert body["format"] == "json"
    assert body["count"] == 1  # only the recent one falls within the last 24h
    assert body["stubs"]["stix2"]["available"] is False


def test_session_export_json_explicit_range(
    client: TestClient,
    state: DashboardState,
) -> None:
    now = datetime.now(tz=UTC)
    portal = client.portal
    assert portal is not None
    portal.call(_seed_state, state, _snapshot(started=now - timedelta(days=2)))
    # The "+" in isoformat()'s "+00:00" is parsed as space in URL
    # query strings; use "Z" instead. params= also URL-encodes safely.
    r = client.get(
        "/api/export/sessions",
        params={
            "from": (now - timedelta(days=3)).isoformat().replace("+00:00", "Z"),
            "to": now.isoformat().replace("+00:00", "Z"),
        },
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["count"] == 1


def test_session_export_rejects_oversize_window(client: TestClient) -> None:
    r = client.get(
        "/api/export/sessions?from=2026-01-01T00:00:00Z&to=2026-02-01T00:00:00Z",
    )
    assert r.status_code == 400
    assert "cap" in r.json()["detail"]


def test_session_export_rejects_inverted_range(client: TestClient) -> None:
    r = client.get(
        "/api/export/sessions?from=2026-05-24T12:00:00Z&to=2026-05-24T11:00:00Z",
    )
    assert r.status_code == 400


# ---------------------------------------------------------------------------
# /api/export/sessions (CSV)
# ---------------------------------------------------------------------------


def test_session_export_csv_streams_with_header_row(
    client: TestClient,
    state: DashboardState,
) -> None:
    now = datetime.now(tz=UTC)
    portal = client.portal
    assert portal is not None
    portal.call(_seed_state, state, _snapshot(started=now - timedelta(hours=2)))
    r = client.get("/api/export/sessions?format=csv")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/csv")
    assert "attachment" in r.headers["content-disposition"]
    lines = r.text.strip().splitlines()
    assert (
        lines[0]
        == "session_id,source_ip,username,started_at,ended_at,command_count,fake_hostname,fake_username"
    )
    assert len(lines) == 2  # header + one row


def test_session_export_csv_header_only_when_empty(
    client: TestClient,
) -> None:
    r = client.get("/api/export/sessions?format=csv")
    lines = r.text.strip().splitlines()
    assert len(lines) == 1
    assert "session_id" in lines[0]


# ---------------------------------------------------------------------------
# /api/export/audit
# ---------------------------------------------------------------------------


def _write_audit_event(audit_path: Path, ts: datetime, event_type: str) -> None:
    line = (
        json.dumps(
            {"ts": ts.isoformat(), "event_type": event_type},
            separators=(",", ":"),
        )
        + "\n"
    )
    with audit_path.open("a", encoding="utf-8") as f:
        f.write(line)


def test_audit_export_filters_to_range(
    client: TestClient,
    audit_path: Path,
) -> None:
    now = datetime.now(tz=UTC)
    # AuditLog.record always appends, so a real audit log is oldest-
    # first in file order. Write the same way here.
    _write_audit_event(audit_path, now - timedelta(days=5), "bridge.defense_fired")
    _write_audit_event(audit_path, now - timedelta(hours=2), "bridge.defense_fired")
    r = client.get("/api/export/audit")
    assert r.status_code == 200
    body = r.json()
    # 24-hour default range; only the recent event is in window.
    assert body["count"] == 1


def test_audit_export_returns_items_oldest_first(
    client: TestClient,
    audit_path: Path,
) -> None:
    now = datetime.now(tz=UTC)
    # Already oldest-first in file order.
    _write_audit_event(audit_path, now - timedelta(minutes=10), "bridge.defense_fired")
    _write_audit_event(audit_path, now - timedelta(minutes=5), "bridge.defense_fired")
    body = client.get("/api/export/audit").json()
    ts_list = [item["ts"] for item in body["items"]]
    assert ts_list == sorted(ts_list)


def test_audit_export_emits_dashboard_export_served(
    client: TestClient,
    audit_path: Path,
) -> None:
    client.get("/api/export/audit")
    text = audit_path.read_text(encoding="utf-8")
    # The endpoint records its own audit event after computing the
    # payload; the latest line should be the dashboard.export_served.
    assert "dashboard.export_served" in text


def test_audit_export_rejects_oversize_range(client: TestClient) -> None:
    r = client.get(
        "/api/export/audit?from=2026-01-01T00:00:00Z&to=2026-02-01T00:00:00Z",
    )
    assert r.status_code == 400


# ---------------------------------------------------------------------------
# Session-export audit event
# ---------------------------------------------------------------------------


def test_session_export_emits_dashboard_export_served(
    client: TestClient,
    audit_path: Path,
) -> None:
    client.get("/api/export/sessions?format=json")
    text = audit_path.read_text(encoding="utf-8")
    assert "dashboard.export_served" in text
    assert "sessions" in text
