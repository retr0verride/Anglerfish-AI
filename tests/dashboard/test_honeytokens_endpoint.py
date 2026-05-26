"""Tests for the Stage 11 slice 11.4 honeytoken dashboard endpoints.

Covers ``GET /api/honeytokens/state`` (registry rows for a
source IP, mirrors ``/api/persistence/state``) and
``GET /api/honeytokens/callbacks`` (recent callback hits read
directly from the audit log).
"""

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
from anglerfish.dashboard import create_app
from anglerfish.dashboard.state import DashboardState
from anglerfish.honeytokens.schema import Honeytoken


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


def _ts(offset_seconds: int) -> str:
    return (datetime.now(tz=UTC) - timedelta(seconds=offset_seconds)).isoformat()


def _write_audit(audit_path: Path, events: list[dict[str, object]]) -> None:
    audit_path.write_text(
        "".join(json.dumps(e, separators=(",", ":")) + "\n" for e in events),
        encoding="utf-8",
    )


# ---------------------------------------------------------------------------
# /api/honeytokens/state
# ---------------------------------------------------------------------------


def test_honeytokens_state_empty_when_no_rows(client: TestClient) -> None:
    body = client.get("/api/honeytokens/state?source_ip=203.0.113.7").json()
    assert body == {
        "source_ip": "203.0.113.7",
        "count": 0,
        "items": [],
    }


async def test_honeytokens_state_returns_rows_oldest_first(
    client: TestClient,
    dashboard_state: DashboardState,
) -> None:
    older = Honeytoken(
        id="AAAAAAAAAAAAAAAA",
        kind="aws",
        payload="[default]\naws_access_key_id=AKIAAAAAAAAAAAAAAAAA\n",
        callback_url="https://honey.example.com/cb/AAAAAAAAAAAAAAAA",
        placed_at="/root/.aws/credentials",
        source_ip="203.0.113.7",
        session_id=uuid4(),
        created_at=datetime(2026, 5, 25, 12, 0, tzinfo=UTC),
    )
    newer = Honeytoken(
        id="BBBBBBBBBBBBBBBB",
        kind="ssh_key",
        payload="-----BEGIN OPENSSH PRIVATE KEY-----\nbody\n-----END OPENSSH PRIVATE KEY-----\n",
        callback_url="https://honey.example.com/cb/BBBBBBBBBBBBBBBB",
        placed_at="/root/.ssh/id_rsa",
        source_ip="203.0.113.7",
        session_id=uuid4(),
        created_at=datetime(2026, 5, 26, 12, 0, tzinfo=UTC),
    )
    await dashboard_state.register_honeytoken(older)
    await dashboard_state.register_honeytoken(newer)

    body = client.get("/api/honeytokens/state?source_ip=203.0.113.7").json()
    assert body["count"] == 2
    assert body["items"][0]["id"] == "AAAAAAAAAAAAAAAA"
    assert body["items"][0]["kind"] == "aws"
    assert body["items"][1]["id"] == "BBBBBBBBBBBBBBBB"


async def test_honeytokens_state_filters_by_source_ip(
    client: TestClient,
    dashboard_state: DashboardState,
) -> None:
    await dashboard_state.register_honeytoken(
        Honeytoken(
            id="CCCCCCCCCCCCCCCC",
            kind="aws",
            payload="[default]\nkey=for-ip-7\n",
            callback_url="https://honey.example.com/cb/CCCCCCCCCCCCCCCC",
            placed_at="/root/.aws/credentials",
            source_ip="203.0.113.7",
            session_id=uuid4(),
            created_at=datetime(2026, 5, 26, 12, 0, tzinfo=UTC),
        ),
    )
    await dashboard_state.register_honeytoken(
        Honeytoken(
            id="DDDDDDDDDDDDDDDD",
            kind="aws",
            payload="[default]\nkey=for-ip-8\n",
            callback_url="https://honey.example.com/cb/DDDDDDDDDDDDDDDD",
            placed_at="/root/.aws/credentials",
            source_ip="203.0.113.8",
            session_id=uuid4(),
            created_at=datetime(2026, 5, 26, 12, 0, tzinfo=UTC),
        ),
    )
    body_7 = client.get("/api/honeytokens/state?source_ip=203.0.113.7").json()
    body_8 = client.get("/api/honeytokens/state?source_ip=203.0.113.8").json()
    assert [it["id"] for it in body_7["items"]] == ["CCCCCCCCCCCCCCCC"]
    assert [it["id"] for it in body_8["items"]] == ["DDDDDDDDDDDDDDDD"]


def test_honeytokens_state_rejects_missing_source_ip(client: TestClient) -> None:
    r = client.get("/api/honeytokens/state")
    assert r.status_code == 422


# ---------------------------------------------------------------------------
# /api/honeytokens/callbacks
# ---------------------------------------------------------------------------


def test_honeytokens_callbacks_empty_when_no_audit_events(
    client: TestClient,
) -> None:
    body = client.get("/api/honeytokens/callbacks").json()
    assert body["count"] == 0
    assert body["items"] == []
    # since defaults to the unix epoch.
    assert body["since"].startswith("1970-01-01")


def test_honeytokens_callbacks_returns_newest_first(
    client: TestClient,
    audit_path: Path,
) -> None:
    # File order is oldest-first (AuditLog appends); the response is
    # newest-first (iter_events_in_range walks the file in reverse).
    _write_audit(
        audit_path,
        [
            {
                "ts": _ts(20),
                "event_type": "bridge.honeytoken_callback",
                "token_id": "AAAAAAAAAAAAAAAA",
                "kind": "aws",
                "registered_source_ip": "203.0.113.7",
                "callback_source_ip": "198.51.100.1",
                "user_agent": "aws-cli/2.13",
                "request_path": "/cb/AAAAAAAAAAAAAAAA",
            },
            {
                "ts": _ts(5),
                "event_type": "bridge.honeytoken_callback",
                "token_id": "BBBBBBBBBBBBBBBB",
                "kind": "ssh_key",
                "registered_source_ip": None,
                "callback_source_ip": "192.0.2.1",
                "user_agent": "curl/7.88",
                "request_path": "/cb/BBBBBBBBBBBBBBBB",
            },
        ],
    )
    body = client.get("/api/honeytokens/callbacks").json()
    assert body["count"] == 2
    assert body["items"][0]["token_id"] == "BBBBBBBBBBBBBBBB"
    assert body["items"][1]["token_id"] == "AAAAAAAAAAAAAAAA"


def test_honeytokens_callbacks_ignores_other_audit_events(
    client: TestClient,
    audit_path: Path,
) -> None:
    _write_audit(
        audit_path,
        [
            {
                "ts": _ts(10),
                "event_type": "bridge.defense_fired",
                "detector": "x",
                "score": 1.0,
            },
            {
                "ts": _ts(5),
                "event_type": "bridge.honeytoken_callback",
                "token_id": "AAAAAAAAAAAAAAAA",
                "kind": "aws",
                "registered_source_ip": "203.0.113.7",
                "callback_source_ip": "198.51.100.1",
                "user_agent": "aws-cli/2.13",
                "request_path": "/cb/AAAAAAAAAAAAAAAA",
            },
        ],
    )
    body = client.get("/api/honeytokens/callbacks").json()
    assert body["count"] == 1
    assert body["items"][0]["token_id"] == "AAAAAAAAAAAAAAAA"


def test_honeytokens_callbacks_rejects_malformed_since(client: TestClient) -> None:
    r = client.get("/api/honeytokens/callbacks?since=not-a-date")
    assert r.status_code == 400


def test_honeytokens_callbacks_limit_enforced(
    client: TestClient,
    audit_path: Path,
) -> None:
    _write_audit(
        audit_path,
        [
            {
                "ts": _ts(i),
                "event_type": "bridge.honeytoken_callback",
                "token_id": "A" * 16,
                "kind": "aws",
                "registered_source_ip": "203.0.113.7",
                "callback_source_ip": "198.51.100.1",
                "user_agent": "aws-cli/2.13",
                "request_path": "/cb/AAAAAAAAAAAAAAAA",
            }
            for i in range(5)
        ],
    )
    body = client.get("/api/honeytokens/callbacks?limit=2").json()
    assert body["count"] == 2
