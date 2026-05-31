"""A naive-but-valid ISO `since` must not 500 three endpoints (audit M5)."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from anglerfish.audit import AuditLog
from anglerfish.config import AnglerfishSettings
from anglerfish.dashboard import create_app
from anglerfish.dashboard.state import DashboardState

# Tz-less but valid ISO-8601. datetime.fromisoformat returns a NAIVE
# datetime for this, which then raised TypeError against the tz-aware
# range bound (HTTP 500) before the fix.
_NAIVE_SINCE = "2020-01-01T00:00:00"


@pytest.fixture
def client(
    settings: AnglerfishSettings,
    tmp_path: Path,
    dashboard_state: DashboardState,
) -> Iterator[TestClient]:
    audit = AuditLog(tmp_path / "audit.jsonl")
    # Seed one of each event the read endpoints scan, so the range scan
    # is actually exercised rather than short-circuiting on an empty log.
    audit.record("bridge.honeytoken_callback", token_id="MFRGGZDFMZTWQ2LK", kind="aws")
    audit.record("bridge.counter_deception_engaged", session_id="x", mode="both")
    app = create_app(settings, state=dashboard_state, audit=audit)
    with TestClient(app) as c:
        yield c


@pytest.mark.parametrize(
    "path",
    [
        "/api/clusters",
        "/api/honeytokens/callbacks",
        "/api/counter_deception/engagements",
    ],
)
def test_naive_iso_since_does_not_500(client: TestClient, path: str) -> None:
    r = client.get(path, params={"since": _NAIVE_SINCE})
    assert r.status_code == 200, f"{path} -> {r.status_code}: {r.text}"


@pytest.mark.parametrize(
    "path",
    [
        "/api/clusters",
        "/api/honeytokens/callbacks",
        "/api/counter_deception/engagements",
    ],
)
def test_malformed_since_still_400(client: TestClient, path: str) -> None:
    r = client.get(path, params={"since": "not-a-timestamp"})
    assert r.status_code == 400, f"{path} -> {r.status_code}: {r.text}"
