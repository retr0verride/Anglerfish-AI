"""Bridge-service integration tests for Stage 10 slice 10.3."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import httpx
import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr

from anglerfish.bridge import AIBridgeService, OllamaClient, create_bridge_app
from anglerfish.bridge.session import SessionContext
from anglerfish.config import (
    AnglerfishSettings,
    BridgeConfig,
    CredentialsConfig,
    DashboardConfig,
)
from anglerfish.config.models import OllamaConfig, SessionStoreConfig
from anglerfish.models.persistence import PersistenceEvent
from anglerfish.persistence import PersistenceClassifier
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
    engaged: bool = True,
) -> AnglerfishSettings:
    return AnglerfishSettings(
        dashboard=DashboardConfig(session_secret=SecretStr(session_secret)),
        credentials=CredentialsConfig(encryption_key=SecretStr(encryption_key_b64)),
        bridge=BridgeConfig(engaged_persistence=engaged),
        sessions=SessionStoreConfig(database_path=sessions_db),
    )


def _make_session(
    *,
    persistence_events: list[PersistenceEvent] | None = None,
) -> SessionContext:
    return SessionContext(
        uuid4(),
        source_ip="203.0.113.7",
        username="root",
        fake_hostname="srv-prod-01",
        fake_username="root",
        fake_cwd="/root",
        history_window=200,
        persistence_events=persistence_events,
    )


# ---------------------------------------------------------------------------
# AIBridgeService.classify_command
# ---------------------------------------------------------------------------


async def test_classify_command_returns_none_when_disabled(
    session_secret: str,
    encryption_key_b64: str,
    tmp_path: Path,
) -> None:
    """engaged_persistence=False short-circuits regardless of classifier wiring."""
    settings = _settings(
        session_secret=session_secret,
        encryption_key_b64=encryption_key_b64,
        sessions_db=tmp_path / "sessions.db",
        engaged=False,
    )
    audit = _CaptureAudit()
    service = AIBridgeService(
        settings,
        client=_mock_client(),
        audit_log=audit,  # type: ignore[arg-type]
        persistence_classifier=PersistenceClassifier(client=None),
    )
    session = _make_session()
    try:
        result = await service.classify_command(
            "echo 'ssh-ed25519 AAAA attacker' >> ~/.ssh/authorized_keys",
            session=session,
        )
    finally:
        await service.aclose()
    assert result is None
    assert not [e for e in audit.events if e[0] == "bridge.persistence_attempt"]


async def test_classify_command_returns_none_when_no_classifier(
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
    session = _make_session()
    try:
        result = await service.classify_command("crontab -e", session=session)
    finally:
        await service.aclose()
    assert result is None


async def test_classify_command_audits_and_records_on_regex_hit(
    session_secret: str,
    encryption_key_b64: str,
    tmp_path: Path,
) -> None:
    """Classifier hits -> SessionContext mutated + bridge.persistence_attempt fires."""
    settings = _settings(
        session_secret=session_secret,
        encryption_key_b64=encryption_key_b64,
        sessions_db=tmp_path / "sessions.db",
    )
    audit = _CaptureAudit()
    service = AIBridgeService(
        settings,
        client=_mock_client(),
        audit_log=audit,  # type: ignore[arg-type]
        persistence_classifier=PersistenceClassifier(client=None),
    )
    session = _make_session()
    try:
        result = await service.classify_command(
            "echo '0 * * * * /tmp/.x' | crontab -",
            session=session,
        )
    finally:
        await service.aclose()
    assert result is not None
    assert result.kind == "crontab"
    # SessionContext now reflects the install for the rest of this session.
    assert len(session.persistence_events) == 1
    assert session.persistence_events[0].payload == "0 * * * * /tmp/.x"
    # Audit emitted with the full payload shape the tailer parser expects.
    fired = [e for e in audit.events if e[0] == "bridge.persistence_attempt"]
    assert len(fired) == 1
    _, fields = fired[0]
    assert fields["kind"] == "crontab"
    assert fields["payload"] == "0 * * * * /tmp/.x"
    assert fields["source"] == "regex"
    assert fields["source_ip"] == "203.0.113.7"
    assert isinstance(fields["created_at"], str)


async def test_classify_command_swallows_classifier_error_and_audits(
    session_secret: str,
    encryption_key_b64: str,
    tmp_path: Path,
) -> None:
    """Classifier-LLM error -> bridge.persistence_classifier_error + None return."""
    from anglerfish.llm.errors import OllamaUnavailableError

    class _RaisingClient:
        async def structured_chat(self, *args, **kwargs):  # type: ignore[no-untyped-def]
            del args, kwargs
            raise OllamaUnavailableError("ollama down")

    settings = _settings(
        session_secret=session_secret,
        encryption_key_b64=encryption_key_b64,
        sessions_db=tmp_path / "sessions.db",
    )
    audit = _CaptureAudit()
    service = AIBridgeService(
        settings,
        client=_mock_client(),
        audit_log=audit,  # type: ignore[arg-type]
        persistence_classifier=PersistenceClassifier(
            client=_RaisingClient(),  # type: ignore[arg-type]
        ),
    )
    session = _make_session()
    try:
        result = await service.classify_command(
            "chmod +x /tmp/.x",
            session=session,
        )
    finally:
        await service.aclose()
    assert result is None
    assert session.persistence_events == ()
    errors = [e for e in audit.events if e[0] == "bridge.persistence_classifier_error"]
    assert len(errors) == 1
    assert "ollama down" in str(errors[0][1]["error"])


# ---------------------------------------------------------------------------
# AIBridgeService.load_persistence_for_source_ip
# ---------------------------------------------------------------------------


@pytest.fixture
async def opened_reader_with_seed(
    tmp_path: Path,
):
    """Migrate the DB + seed a prior install, then yield (reader, sessions_db)."""
    sessions_db = tmp_path / "sessions.db"
    config = SessionStoreConfig(database_path=sessions_db)
    writer = SessionStore(config)
    await writer.open()
    await writer.record_persistence_event(
        PersistenceEvent(
            kind="crontab",
            sub_key=None,
            payload="0 * * * * /tmp/.x",
            source="regex",
        ),
        source_ip="203.0.113.7",
        session_id=uuid4(),
        created_at=datetime(2026, 5, 26, 12, 0, tzinfo=UTC),
    )
    await writer.aclose()
    reader = SessionStoreReader(config)
    await reader.open()
    try:
        yield reader, sessions_db
    finally:
        await reader.aclose()


async def test_load_persistence_returns_prior_installs(
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
        events = await service.load_persistence_for_source_ip("203.0.113.7")
    finally:
        await service.aclose()
    assert len(events) == 1
    assert events[0].payload == "0 * * * * /tmp/.x"


async def test_load_persistence_empty_when_disabled(
    session_secret: str,
    encryption_key_b64: str,
    opened_reader_with_seed,
) -> None:
    reader, sessions_db = opened_reader_with_seed
    settings = _settings(
        session_secret=session_secret,
        encryption_key_b64=encryption_key_b64,
        sessions_db=sessions_db,
        engaged=False,
    )
    service = AIBridgeService(
        settings,
        client=_mock_client(),
        session_store_reader=reader,
    )
    try:
        events = await service.load_persistence_for_source_ip("203.0.113.7")
    finally:
        await service.aclose()
    assert events == []


async def test_load_persistence_empty_when_no_reader(
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
        events = await service.load_persistence_for_source_ip("203.0.113.7")
    finally:
        await service.aclose()
    assert events == []


# ---------------------------------------------------------------------------
# HTTP /command end-to-end (TestClient drives the full pipeline)
# ---------------------------------------------------------------------------


def test_command_endpoint_runs_classifier_and_audits_install(
    session_secret: str,
    encryption_key_b64: str,
    tmp_path: Path,
) -> None:
    import asyncio

    sessions_db = tmp_path / "sessions.db"
    # Migrate the DB via a writer so the reader can open it.
    writer = SessionStore(SessionStoreConfig(database_path=sessions_db))
    asyncio.run(writer.open())
    asyncio.run(writer.aclose())

    settings = _settings(
        session_secret=session_secret,
        encryption_key_b64=encryption_key_b64,
        sessions_db=sessions_db,
    )
    audit = _CaptureAudit()
    reader = SessionStoreReader(settings.sessions)
    asyncio.run(reader.open())
    service = AIBridgeService(
        settings,
        client=_mock_client(),
        audit_log=audit,  # type: ignore[arg-type]
        persistence_classifier=PersistenceClassifier(client=None),
        session_store_reader=reader,
    )
    app = create_bridge_app(service)
    with TestClient(app) as c:
        body = c.post(
            "/api/v1/session",
            json={"source_ip": "203.0.113.7", "username": "root"},
        ).json()
        sid = body["session_id"]
        c.post(
            f"/api/v1/session/{sid}/command",
            json={"command": "echo '0 * * * * /tmp/.x' | crontab -"},
        )

    fired = [e for e in audit.events if e[0] == "bridge.persistence_attempt"]
    assert len(fired) == 1
    assert fired[0][1]["kind"] == "crontab"


def test_session_open_seeds_persistence_from_prior_install(
    session_secret: str,
    encryption_key_b64: str,
    tmp_path: Path,
) -> None:
    """A second session from the same IP sees the prior install pre-loaded."""
    import asyncio

    sessions_db = tmp_path / "sessions.db"
    # Seed a prior install directly.
    writer = SessionStore(SessionStoreConfig(database_path=sessions_db))

    async def _seed() -> None:
        await writer.open()
        await writer.record_persistence_event(
            PersistenceEvent(
                kind="authorized_keys",
                sub_key=None,
                payload="ssh-ed25519 AAAA prior@x",
                source="regex",
            ),
            source_ip="203.0.113.7",
            session_id=uuid4(),
            created_at=datetime(2026, 5, 25, 12, 0, tzinfo=UTC),
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
        persistence_classifier=PersistenceClassifier(client=None),
        session_store_reader=reader,
    )
    app = create_bridge_app(service)
    with TestClient(app) as c:
        body = c.post(
            "/api/v1/session",
            json={"source_ip": "203.0.113.7", "username": "root"},
        ).json()
        sid = body["session_id"]

    # Pull the live SessionContext to assert the prior install was seeded.
    ctx = app.state.sessions[uuid_module.UUID(sid)]
    events = ctx.persistence_events
    assert len(events) == 1
    assert events[0].payload == "ssh-ed25519 AAAA prior@x"


import uuid as uuid_module  # noqa: E402  - used by test above
