"""Tests for the Stage 3 alerts endpoint."""

from __future__ import annotations

import json
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
    app = create_app(settings, audit=AuditLog(audit_path))
    with TestClient(app) as c:
        yield c


def _write_events(audit_path: Path, events: list[dict[str, object]]) -> None:
    audit_path.write_text(
        "".join(json.dumps(e, separators=(",", ":")) + "\n" for e in events),
        encoding="utf-8",
    )


def _ts(offset_seconds: int) -> str:
    return (datetime.now(tz=UTC) - timedelta(seconds=offset_seconds)).isoformat()


# ---------------------------------------------------------------------------
# Empty / no-data behaviour
# ---------------------------------------------------------------------------


def test_alerts_endpoint_returns_empty_page_with_stubs_when_no_events(
    client: TestClient,
) -> None:
    body = client.get("/api/alerts").json()
    assert body["items"] == []
    assert body["next_cursor"] is None
    stubs = body["stubs"]
    assert stubs["honeytoken_callback_hits"]["available"] is False
    assert stubs["behavioral_cluster_matches"]["available"] is False
    # intent_summary_alerts flipped to live in Stage 7 slice 4 and is
    # therefore no longer in the stub list (operators see real events
    # at /api/alerts?kind=intent_summary).
    assert "intent_summary_alerts" not in stubs


# ---------------------------------------------------------------------------
# Event surfacing per kind
# ---------------------------------------------------------------------------


def test_alerts_surfaces_defense_fired_events(
    client: TestClient,
    audit_path: Path,
) -> None:
    _write_events(
        audit_path,
        [
            {
                "ts": _ts(10),  # one event; file order doesn't matter
                "event_type": "bridge.defense_fired",
                "detector": "injection:override_instructions",
                "score": 1.0,
                "session_id": "abc-123",
                "attacker_ip": "203.0.113.7",
            },
        ],
    )
    body = client.get("/api/alerts").json()
    assert len(body["items"]) == 1
    item = body["items"][0]
    assert item["kind"] == "defense_fired"
    assert item["session_id"] == "abc-123"
    assert item["source_ip"] == "203.0.113.7"
    assert "override_instructions" in item["detail"]


def test_alerts_surfaces_subsystem_refused(
    client: TestClient,
    audit_path: Path,
) -> None:
    _write_events(
        audit_path,
        [
            {
                "ts": _ts(5),
                "event_type": "lure.subsystem_refused",
                "kind": "direct-tcpip",
                "source_ip": "198.51.100.10",
            },
        ],
    )
    body = client.get("/api/alerts").json()
    assert body["items"][0]["kind"] == "subsystem_refused"
    assert body["items"][0]["source_ip"] == "198.51.100.10"


def test_alerts_ignores_non_alert_event_types(
    client: TestClient,
    audit_path: Path,
) -> None:
    _write_events(
        audit_path,
        # Oldest first (20s ago, then 10s ago).
        [
            {"ts": _ts(20), "event_type": "lure.session_opened"},
            {"ts": _ts(10), "event_type": "bridge.command_bridge"},
        ],
    )
    body = client.get("/api/alerts").json()
    assert body["items"] == []


# ---------------------------------------------------------------------------
# Pagination
# ---------------------------------------------------------------------------


def test_alerts_paginates_with_cursor(
    client: TestClient,
    audit_path: Path,
) -> None:
    # AuditLog.record always appends, so a real log is oldest-first in
    # file order. Reproduce that here by emitting cat6 (oldest) on
    # line 1, cat0 (newest) on line 7.
    events = [
        {
            "ts": _ts(i),
            "event_type": "bridge.defense_fired",
            "detector": f"injection:cat{i}",
            "score": 1.0,
        }
        for i in (6, 5, 4, 3, 2, 1, 0)
    ]
    _write_events(audit_path, events)

    first = client.get("/api/alerts?limit=3").json()
    assert len(first["items"]) == 3
    assert first["next_cursor"] is not None

    second = client.get(f"/api/alerts?limit=3&cursor={first['next_cursor']}").json()
    assert len(second["items"]) == 3
    # No overlap between pages.
    first_ids = {i["id"] for i in first["items"]}
    second_ids = {i["id"] for i in second["items"]}
    assert first_ids.isdisjoint(second_ids)


def test_alerts_pagination_terminates(
    client: TestClient,
    audit_path: Path,
) -> None:
    # Oldest-first file order, matching AuditLog.record behaviour.
    events = [
        {
            "ts": _ts(i),
            "event_type": "bridge.defense_fired",
            "detector": "x",
            "score": 1.0,
        }
        for i in (2, 1, 0)
    ]
    _write_events(audit_path, events)
    body = client.get("/api/alerts?limit=10").json()
    assert len(body["items"]) == 3
    # Page was not full, so no next cursor.
    assert body["next_cursor"] is None


# ---------------------------------------------------------------------------
# kind filter
# ---------------------------------------------------------------------------


def test_alerts_kind_filter_narrows(
    client: TestClient,
    audit_path: Path,
) -> None:
    _write_events(
        audit_path,
        # Oldest first (20s ago refused, then 10s ago defense_fired).
        [
            {
                "ts": _ts(20),
                "event_type": "lure.subsystem_refused",
                "kind": "sftp",
            },
            {
                "ts": _ts(10),
                "event_type": "bridge.defense_fired",
                "detector": "x",
                "score": 1.0,
            },
        ],
    )
    body = client.get("/api/alerts?kind=defense_fired").json()
    assert len(body["items"]) == 1
    assert body["items"][0]["kind"] == "defense_fired"


def test_alerts_unknown_kind_returns_empty(
    client: TestClient,
    audit_path: Path,
) -> None:
    _write_events(
        audit_path,
        [
            {
                "ts": _ts(10),
                "event_type": "bridge.defense_fired",
                "detector": "x",
                "score": 1.0,
            },
        ],
    )
    body = client.get("/api/alerts?kind=not-a-real-kind").json()
    assert body["items"] == []
    # Stubs still rendered on the unknown-kind path.
    assert "stubs" in body


# ---------------------------------------------------------------------------
# Audit event
# ---------------------------------------------------------------------------


def test_alerts_fetch_emits_dashboard_audit_read(
    client: TestClient,
    audit_path: Path,
) -> None:
    client.get("/api/alerts")
    text = audit_path.read_text(encoding="utf-8")
    assert "dashboard.audit_read" in text
