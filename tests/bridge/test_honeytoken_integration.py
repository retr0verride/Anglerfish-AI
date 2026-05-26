"""Bridge integration tests for Stage 11 slice 11.3."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import httpx
import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr

from anglerfish.bridge import AIBridgeService, OllamaClient, create_bridge_app
from anglerfish.config import (
    AnglerfishSettings,
    BridgeConfig,
    CredentialsConfig,
    DashboardConfig,
    HoneytokensConfig,
)
from anglerfish.config.models import OllamaConfig, SessionStoreConfig
from anglerfish.honeytokens import (
    Honeytoken,
    HoneytokenGenerator,
    HoneytokenPlacementService,
)
from anglerfish.models.threat import ThreatAssessment
from anglerfish.sessions import SessionStore
from anglerfish.sessions.reader import SessionStoreReader

_Handler = Callable[[httpx.Request], httpx.Response]


class _CaptureAudit:
    def __init__(self) -> None:
        self.events: list[tuple[str, dict[str, object]]] = []

    def record(self, event_type: str, **fields: object) -> None:
        self.events.append((event_type, fields))


def _mock_client() -> OllamaClient:
    def handler(_req: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "message": {"content": "ok\n"},
                "done": True,
                "prompt_eval_count": 1,
                "eval_count": 1,
            },
        )

    transport = httpx.MockTransport(handler)
    http = httpx.AsyncClient(base_url="http://127.0.0.1:11434", transport=transport)
    return OllamaClient(OllamaConfig(), http_client=http)


def _settings(
    *,
    session_secret: str,
    encryption_key_b64: str,
    sessions_db: Path,
    enabled: bool = True,
    threshold: int = 50,
) -> AnglerfishSettings:
    return AnglerfishSettings(
        dashboard=DashboardConfig(session_secret=SecretStr(session_secret)),
        credentials=CredentialsConfig(encryption_key=SecretStr(encryption_key_b64)),
        bridge=BridgeConfig(),
        sessions=SessionStoreConfig(database_path=sessions_db),
        honeytokens=HoneytokensConfig(
            enabled=enabled,
            callback_base_url="https://honey.example.com" if enabled else None,
            placement_threshold=threshold,
        ),
    )


def _threat(score: int) -> ThreatAssessment:
    return ThreatAssessment(
        session_id=uuid4(),
        score=score,
        persistence_attempted=False,
        high_severity=score >= 70,
        techniques=(),
        notes=(),
    )


# ---------------------------------------------------------------------------
# Threshold hook
# ---------------------------------------------------------------------------


async def test_record_threat_assessment_above_threshold_schedules_placement(
    session_secret: str,
    encryption_key_b64: str,
    tmp_path: Path,
) -> None:
    audit = _CaptureAudit()
    settings = _settings(
        session_secret=session_secret,
        encryption_key_b64=encryption_key_b64,
        sessions_db=tmp_path / "sessions.db",
        threshold=50,
    )
    placement = HoneytokenPlacementService(
        generator=HoneytokenGenerator(callback_base_url="https://honey.example.com"),
        audit_log=audit,  # type: ignore[arg-type]
    )
    service = AIBridgeService(
        settings,
        client=_mock_client(),
        audit_log=audit,  # type: ignore[arg-type]
        honeytoken_placement=placement,
    )
    sid = uuid4()
    service.record_session_source_ip(sid, "203.0.113.7")
    try:
        threat = _threat(score=75).model_copy(update={"session_id": sid})
        service.record_threat_assessment(sid, threat)
        # Wait for all background placement tasks.
        await asyncio.gather(*placement._tasks, return_exceptions=True)  # type: ignore[attr-defined]
    finally:
        await service.aclose()
    placed = [e for e in audit.events if e[0] == "bridge.honeytoken_placed"]
    assert len(placed) == 2


async def test_record_threat_assessment_below_threshold_no_placement(
    session_secret: str,
    encryption_key_b64: str,
    tmp_path: Path,
) -> None:
    audit = _CaptureAudit()
    settings = _settings(
        session_secret=session_secret,
        encryption_key_b64=encryption_key_b64,
        sessions_db=tmp_path / "sessions.db",
        threshold=80,
    )
    placement = HoneytokenPlacementService(
        generator=HoneytokenGenerator(callback_base_url="https://honey.example.com"),
        audit_log=audit,  # type: ignore[arg-type]
    )
    service = AIBridgeService(
        settings,
        client=_mock_client(),
        audit_log=audit,  # type: ignore[arg-type]
        honeytoken_placement=placement,
    )
    sid = uuid4()
    service.record_session_source_ip(sid, "203.0.113.7")
    try:
        service.record_threat_assessment(sid, _threat(score=70))
        # No task scheduled means the await on the empty set is trivial.
        await asyncio.gather(*placement._tasks, return_exceptions=True)  # type: ignore[attr-defined]
    finally:
        await service.aclose()
    assert not [e for e in audit.events if e[0] == "bridge.honeytoken_placed"]


async def test_record_threat_assessment_disabled_no_placement(
    session_secret: str,
    encryption_key_b64: str,
    tmp_path: Path,
) -> None:
    """honeytokens.enabled=False short-circuits even with a placement wired."""
    audit = _CaptureAudit()
    settings = _settings(
        session_secret=session_secret,
        encryption_key_b64=encryption_key_b64,
        sessions_db=tmp_path / "sessions.db",
        enabled=False,
    )
    placement = HoneytokenPlacementService(
        generator=HoneytokenGenerator(callback_base_url="https://honey.example.com"),
        audit_log=audit,  # type: ignore[arg-type]
    )
    service = AIBridgeService(
        settings,
        client=_mock_client(),
        audit_log=audit,  # type: ignore[arg-type]
        honeytoken_placement=placement,
    )
    sid = uuid4()
    service.record_session_source_ip(sid, "203.0.113.7")
    try:
        service.record_threat_assessment(sid, _threat(score=99))
    finally:
        await service.aclose()
    assert not [e for e in audit.events if e[0] == "bridge.honeytoken_placed"]


async def test_record_threat_assessment_dedups_per_session(
    session_secret: str,
    encryption_key_b64: str,
    tmp_path: Path,
) -> None:
    """Repeated above-threshold scores for the same session: placement once."""
    audit = _CaptureAudit()
    settings = _settings(
        session_secret=session_secret,
        encryption_key_b64=encryption_key_b64,
        sessions_db=tmp_path / "sessions.db",
        threshold=50,
    )
    placement = HoneytokenPlacementService(
        generator=HoneytokenGenerator(callback_base_url="https://honey.example.com"),
        audit_log=audit,  # type: ignore[arg-type]
    )
    service = AIBridgeService(
        settings,
        client=_mock_client(),
        audit_log=audit,  # type: ignore[arg-type]
        honeytoken_placement=placement,
    )
    sid = uuid4()
    service.record_session_source_ip(sid, "203.0.113.7")
    try:
        # Fire three times above threshold for the same session.
        for score in (75, 90, 100):
            service.record_threat_assessment(sid, _threat(score=score))
        await asyncio.gather(*placement._tasks, return_exceptions=True)  # type: ignore[attr-defined]
    finally:
        await service.aclose()
    placed = [e for e in audit.events if e[0] == "bridge.honeytoken_placed"]
    assert len(placed) == 2  # one AWS + one SSH; placed exactly once


async def test_record_threat_assessment_no_source_ip_skipped(
    session_secret: str,
    encryption_key_b64: str,
    tmp_path: Path,
) -> None:
    """No record_session_source_ip call beforehand: hook skips silently."""
    audit = _CaptureAudit()
    settings = _settings(
        session_secret=session_secret,
        encryption_key_b64=encryption_key_b64,
        sessions_db=tmp_path / "sessions.db",
    )
    placement = HoneytokenPlacementService(
        generator=HoneytokenGenerator(callback_base_url="https://honey.example.com"),
        audit_log=audit,  # type: ignore[arg-type]
    )
    service = AIBridgeService(
        settings,
        client=_mock_client(),
        audit_log=audit,  # type: ignore[arg-type]
        honeytoken_placement=placement,
    )
    try:
        service.record_threat_assessment(uuid4(), _threat(score=99))
    finally:
        await service.aclose()
    assert not [e for e in audit.events if e[0] == "bridge.honeytoken_placed"]


# ---------------------------------------------------------------------------
# load_honeytokens_for_source_ip
# ---------------------------------------------------------------------------


@pytest.fixture
async def opened_reader_with_seed(
    tmp_path: Path,
):
    """Seed one per-IP + one static-base token, then yield (reader, db_path)."""
    sessions_db = tmp_path / "sessions.db"
    config = SessionStoreConfig(database_path=sessions_db)
    writer = SessionStore(config)
    await writer.open()
    await writer.register_honeytoken(
        Honeytoken(
            id="PERSESSIONAAAAAA",
            kind="aws",
            payload="[default]\naws_access_key_id = AKIAPERSESSIONAAAAAA\n",
            callback_url="https://honey.example.com/cb/PERSESSIONAAAAAA",
            placed_at="/root/.aws/credentials",
            source_ip="203.0.113.7",
            session_id=uuid4(),
            created_at=datetime(2026, 5, 26, 12, 0, tzinfo=UTC),
        ),
    )
    await writer.register_honeytoken(
        Honeytoken(
            id="STATICAAAAAAAAAA",
            kind="ssh_key",
            payload="-----BEGIN OPENSSH PRIVATE KEY-----\nstatic\n",
            callback_url="https://honey.example.com/cb/STATICAAAAAAAAAA",
            placed_at="/root/.ssh/id_rsa",
            source_ip=None,
            session_id=None,
            created_at=datetime(2026, 5, 25, 12, 0, tzinfo=UTC),
        ),
    )
    await writer.aclose()
    reader = SessionStoreReader(config)
    await reader.open()
    try:
        yield reader, sessions_db
    finally:
        await reader.aclose()


async def test_load_honeytokens_merges_static_and_per_ip(
    session_secret: str,
    encryption_key_b64: str,
    opened_reader_with_seed,
) -> None:
    reader, sessions_db = opened_reader_with_seed
    settings = _settings(
        session_secret=session_secret,
        encryption_key_b64=encryption_key_b64,
        sessions_db=sessions_db,
    )
    service = AIBridgeService(
        settings,
        client=_mock_client(),
        session_store_reader=reader,
    )
    try:
        tokens = await service.load_honeytokens_for_source_ip("203.0.113.7")
    finally:
        await service.aclose()
    # Static first (sorted by created_at), then per-IP.
    assert [t.id for t in tokens] == ["STATICAAAAAAAAAA", "PERSESSIONAAAAAA"]


async def test_load_honeytokens_empty_when_disabled(
    session_secret: str,
    encryption_key_b64: str,
    opened_reader_with_seed,
) -> None:
    reader, sessions_db = opened_reader_with_seed
    settings = _settings(
        session_secret=session_secret,
        encryption_key_b64=encryption_key_b64,
        sessions_db=sessions_db,
        enabled=False,
    )
    service = AIBridgeService(
        settings,
        client=_mock_client(),
        session_store_reader=reader,
    )
    try:
        tokens = await service.load_honeytokens_for_source_ip("203.0.113.7")
    finally:
        await service.aclose()
    assert tokens == []


async def test_load_honeytokens_empty_when_no_reader(
    session_secret: str,
    encryption_key_b64: str,
    tmp_path: Path,
) -> None:
    settings = _settings(
        session_secret=session_secret,
        encryption_key_b64=encryption_key_b64,
        sessions_db=tmp_path / "sessions.db",
    )
    service = AIBridgeService(settings, client=_mock_client())
    try:
        tokens = await service.load_honeytokens_for_source_ip("203.0.113.7")
    finally:
        await service.aclose()
    assert tokens == []


# ---------------------------------------------------------------------------
# POST /api/v1/session end-to-end: honeytokens merge into fakefs_overlay
# ---------------------------------------------------------------------------


def test_session_open_merges_honeytokens_into_overlay(
    session_secret: str,
    encryption_key_b64: str,
    tmp_path: Path,
) -> None:
    sessions_db = tmp_path / "sessions.db"

    async def _seed() -> None:
        writer = SessionStore(SessionStoreConfig(database_path=sessions_db))
        await writer.open()
        await writer.register_honeytoken(
            Honeytoken(
                id="STATICAAAAAAAAAA",
                kind="aws",
                payload="[default]\naws_access_key_id = AKIASTATICAAAAAAAAAA\n",
                callback_url="https://honey.example.com/cb/STATICAAAAAAAAAA",
                placed_at="/root/.aws/credentials",
                source_ip=None,
                session_id=None,
                created_at=datetime(2026, 5, 25, 12, 0, tzinfo=UTC),
            ),
        )
        await writer.aclose()

    asyncio.run(_seed())

    settings = _settings(
        session_secret=session_secret,
        encryption_key_b64=encryption_key_b64,
        sessions_db=sessions_db,
    )
    reader = SessionStoreReader(settings.sessions)
    asyncio.run(reader.open())
    service = AIBridgeService(
        settings,
        client=_mock_client(),
        session_store_reader=reader,
    )
    app = create_bridge_app(service)
    with TestClient(app) as c:
        body = c.post(
            "/api/v1/session",
            json={"source_ip": "203.0.113.99", "username": "root"},
        ).json()
    overlay = body["persona_overlay"]
    assert "/root/.aws/credentials" in overlay
    assert "AKIASTATICAAAAAAAAAA" in overlay["/root/.aws/credentials"]
