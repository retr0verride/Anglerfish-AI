"""Tests for the Stage 11 slice 11.4 callback receiver."""

from __future__ import annotations

import json
from collections.abc import AsyncIterator, Iterator
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import pytest
import pytest_asyncio
from fastapi.testclient import TestClient

from anglerfish.audit import AuditLog
from anglerfish.callback import create_callback_app
from anglerfish.config import AnglerfishSettings
from anglerfish.honeytokens.schema import Honeytoken
from anglerfish.sessions import SessionStore
from anglerfish.sessions.reader import SessionStoreReader


@pytest.fixture
def audit_path(tmp_path: Path) -> Path:
    return tmp_path / "callback_audit.jsonl"


@pytest_asyncio.fixture
async def seeded_reader(
    session_store: SessionStore,
    settings: AnglerfishSettings,
) -> AsyncIterator[SessionStoreReader]:
    """Open a SessionStoreReader against a writer-seeded DB.

    The reader is opened before the test runs (the dashboard owns
    DB creation in production; tests get the same ordering by
    having the writer fixture run first). aclose runs after the
    test so the SQLite handle is released cleanly.
    """
    # Seed one known token so the hit-path test has something to find.
    await session_store.register_honeytoken(
        Honeytoken(
            id="AAAAAAAAAAAAAAAA",
            kind="aws",
            payload="[default]\naws_access_key_id=AKIAAAAAAAAAAAAAAAAA\n",
            callback_url="https://honey.example.com/cb/AAAAAAAAAAAAAAAA",
            placed_at="/root/.aws/credentials",
            source_ip="203.0.113.7",
            session_id=uuid4(),
            created_at=datetime(2026, 5, 26, 12, 0, tzinfo=UTC),
        ),
    )
    reader = SessionStoreReader(settings.sessions)
    await reader.open()
    try:
        yield reader
    finally:
        await reader.aclose()


@pytest.fixture
def client(
    settings: AnglerfishSettings,
    audit_path: Path,
    seeded_reader: SessionStoreReader,
) -> Iterator[TestClient]:
    audit = AuditLog(audit_path)
    app = create_callback_app(settings, store_reader=seeded_reader, audit=audit)
    with TestClient(app) as c:
        yield c


def _audit_events(audit_path: Path) -> list[dict[str, object]]:
    if not audit_path.exists():
        return []
    return [
        json.loads(line)
        for line in audit_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


# ---------------------------------------------------------------------------
# Health probe
# ---------------------------------------------------------------------------


def test_health_returns_ok(client: TestClient) -> None:
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}


# ---------------------------------------------------------------------------
# Honeytoken callback hits
# ---------------------------------------------------------------------------


def test_callback_unknown_token_returns_aws_style_403(
    client: TestClient,
    audit_path: Path,
) -> None:
    r = client.get("/cb/ZZZZZZZZZZZZZZZZ")
    assert r.status_code == 403
    assert r.headers["content-type"].startswith("application/xml")
    body = r.text
    assert "<Code>InvalidAccessKeyId</Code>" in body
    assert "AKIAZZZZZZZZZZZZZZZZ" in body
    # Miss is still audited so operators see probe traffic.
    events = _audit_events(audit_path)
    assert len(events) == 1
    assert events[0]["event_type"] == "bridge.honeytoken_callback"
    assert events[0]["registered_source_ip"] is None
    assert events[0]["kind"] is None


def test_callback_known_token_audits_with_registered_fields(
    client: TestClient,
    audit_path: Path,
) -> None:
    r = client.get(
        "/cb/AAAAAAAAAAAAAAAA",
        headers={"User-Agent": "aws-cli/2.13", "X-Forwarded-For": "198.51.100.42"},
    )
    assert r.status_code == 403
    assert "AKIAAAAAAAAAAAAAAAAA" in r.text
    events = _audit_events(audit_path)
    assert len(events) == 1
    event = events[0]
    assert event["event_type"] == "bridge.honeytoken_callback"
    assert event["token_id"] == "AAAAAAAAAAAAAAAA"
    assert event["kind"] == "aws"
    assert event["registered_source_ip"] == "203.0.113.7"
    assert event["callback_source_ip"] == "198.51.100.42"
    assert event["user_agent"] == "aws-cli/2.13"
    assert event["request_path"] == "/cb/AAAAAAAAAAAAAAAA"


def test_callback_rejects_malformed_token_id_without_registry_lookup(
    client: TestClient,
    audit_path: Path,
) -> None:
    """Lowercase / wrong length / non-base32 fall through the regex gate.

    The response is still a 403 AWS-style body (so probes cannot
    enumerate the registry), but no audit line lands.
    """
    r = client.get("/cb/lowercase-and-bad")
    assert r.status_code == 403
    # No audit lines emitted on the regex-reject path.
    assert _audit_events(audit_path) == []


def test_callback_truncates_oversized_user_agent(
    client: TestClient,
    audit_path: Path,
) -> None:
    oversized = "A" * 2000
    client.get(
        "/cb/AAAAAAAAAAAAAAAA",
        headers={"User-Agent": oversized},
    )
    events = _audit_events(audit_path)
    assert len(events) == 1
    ua = events[0]["user_agent"]
    assert isinstance(ua, str)
    assert len(ua) <= 512


def test_callback_missing_token_id_path_component_returns_404(
    client: TestClient,
) -> None:
    """``/cb/`` with no token id is a 404 from FastAPI, not a 403."""
    r = client.get("/cb/")
    # Trailing-slash path is not registered; FastAPI 404s.
    assert r.status_code == 404


def test_callback_x_forwarded_for_picks_leftmost_entry(
    client: TestClient,
    audit_path: Path,
) -> None:
    client.get(
        "/cb/AAAAAAAAAAAAAAAA",
        headers={"X-Forwarded-For": "198.51.100.7, 10.0.0.1"},
    )
    events = _audit_events(audit_path)
    assert events[0]["callback_source_ip"] == "198.51.100.7"
