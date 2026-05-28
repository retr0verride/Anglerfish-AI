"""Bridge-side integration tests for Stage 8 slice 4 embedding generation."""

from __future__ import annotations

import asyncio
import json
from collections.abc import Callable
from datetime import UTC, datetime
from uuid import uuid4

import httpx
from pydantic import SecretStr

from anglerfish.bridge.client import OllamaClient
from anglerfish.bridge.service import AIBridgeService
from anglerfish.bridge.session import SessionContext
from anglerfish.config import (
    AnglerfishSettings,
    BridgeConfig,
    CredentialsConfig,
    DashboardConfig,
)
from anglerfish.config.models import OllamaConfig
from anglerfish.intel import EmbeddingGenerator
from anglerfish.models import ResponseSource
from anglerfish.models.embedding import SessionEmbedding
from anglerfish.models.session import SessionSnapshot

_Handler = Callable[[httpx.Request], httpx.Response]


class _MockAudit:
    def __init__(self) -> None:
        self.events: list[tuple[str, dict[str, object]]] = []

    def record(self, event_type: str, **fields: object) -> None:
        self.events.append((event_type, fields))


def _mock_client(handler: _Handler) -> OllamaClient:
    transport = httpx.MockTransport(handler)
    http = httpx.AsyncClient(base_url="http://127.0.0.1:11434", transport=transport)
    return OllamaClient(OllamaConfig(), http_client=http)


def _make_session(*, n_commands: int = 5) -> SessionContext:
    ctx = SessionContext(
        uuid4(),
        source_ip="203.0.113.7",
        username="root",
        fake_hostname="srv-prod-01",
        fake_username="root",
        fake_cwd="/root",
        history_window=200,
    )
    for i in range(n_commands):
        ctx.record(
            f"cmd-{i}",
            f"output-{i}",
            source=ResponseSource.AI,
            latency_ms=10.0,
        )
    return ctx


def _settings(
    *,
    session_secret: str,
    encryption_key_b64: str,
    embedding_enabled: bool = True,
    embedding_timeout_s: float = 60.0,
) -> AnglerfishSettings:
    return AnglerfishSettings(
        dashboard=DashboardConfig(session_secret=SecretStr(session_secret)),
        credentials=CredentialsConfig(encryption_key=SecretStr(encryption_key_b64)),
        bridge=BridgeConfig(
            embedding_enabled=embedding_enabled,
            embedding_timeout_s=embedding_timeout_s,
        ),
    )


def _embed_response_handler(vector: list[float]) -> _Handler:
    """Mock /api/embed responses with a fixed vector."""

    def handler(_req: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "embedding": vector,
                "prompt_eval_count": 64,
            },
        )

    return handler


# ---------------------------------------------------------------------------
# Schedule + run
# ---------------------------------------------------------------------------


async def test_schedule_embedding_audits_on_success(
    session_secret: str,
    encryption_key_b64: str,
) -> None:
    """Successful generate() emits bridge.embedding_generated with vector."""
    audit = _MockAudit()
    vector = [0.01 * i for i in range(64)]
    client = _mock_client(_embed_response_handler(vector))
    generator = EmbeddingGenerator(client, min_commands=3)
    service = AIBridgeService(
        _settings(
            session_secret=session_secret,
            encryption_key_b64=encryption_key_b64,
        ),
        client=client,
        audit_log=audit,  # type: ignore[arg-type]
        embedding_generator=generator,
    )
    session = _make_session(n_commands=5)
    try:
        task = service.schedule_embedding_generation(session.snapshot())
        assert task is not None
        await task
    finally:
        await service.aclose()

    events = [e for e in audit.events if e[0] == "bridge.embedding_generated"]
    assert len(events) == 1
    _, fields = events[0]
    assert fields["session_id"] == str(session.session_id)
    assert fields["dimension"] == 64
    assert fields["model"]  # some non-empty embed-tier model name
    assert isinstance(fields["vector"], list)
    assert len(fields["vector"]) == 64


async def test_schedule_embedding_audits_skip_for_short_session(
    session_secret: str,
    encryption_key_b64: str,
) -> None:
    """Sessions below min_commands produce bridge.embedding_skipped."""
    audit = _MockAudit()
    client = _mock_client(_embed_response_handler([0.0] * 64))
    generator = EmbeddingGenerator(client, min_commands=10)
    service = AIBridgeService(
        _settings(
            session_secret=session_secret,
            encryption_key_b64=encryption_key_b64,
        ),
        client=client,
        audit_log=audit,  # type: ignore[arg-type]
        embedding_generator=generator,
    )
    session = _make_session(n_commands=2)
    try:
        task = service.schedule_embedding_generation(session.snapshot())
        assert task is not None
        await task
    finally:
        await service.aclose()

    skipped = [e for e in audit.events if e[0] == "bridge.embedding_skipped"]
    assert len(skipped) == 1
    assert skipped[0][1]["reason"] == "below_min_commands"
    assert not any(e[0] == "bridge.embedding_generated" for e in audit.events)


async def test_schedule_embedding_audits_on_llm_failure(
    session_secret: str,
    encryption_key_b64: str,
) -> None:
    """LLM 5xx -> embedding_failed (never raises to the background task loop)."""
    audit = _MockAudit()

    def handler(_req: httpx.Request) -> httpx.Response:
        return httpx.Response(503, text="overloaded")

    client = _mock_client(handler)
    generator = EmbeddingGenerator(client, min_commands=3)
    service = AIBridgeService(
        _settings(
            session_secret=session_secret,
            encryption_key_b64=encryption_key_b64,
        ),
        client=client,
        audit_log=audit,  # type: ignore[arg-type]
        embedding_generator=generator,
    )
    session = _make_session(n_commands=5)
    try:
        task = service.schedule_embedding_generation(session.snapshot())
        assert task is not None
        await task  # must not raise
    finally:
        await service.aclose()

    failed = [e for e in audit.events if e[0] == "bridge.embedding_failed"]
    assert len(failed) == 1
    _, fields = failed[0]
    assert fields["error_type"] == "OllamaUnavailableError"


async def test_schedule_embedding_audits_on_timeout(
    session_secret: str,
    encryption_key_b64: str,
) -> None:
    """A stuck generator trips the wall-clock timeout."""
    audit = _MockAudit()

    class _NeverFinish(EmbeddingGenerator):
        async def generate(self, snapshot: SessionSnapshot) -> SessionEmbedding | None:
            del snapshot
            await asyncio.sleep(10.0)
            raise AssertionError("should not reach")

    client = _mock_client(_embed_response_handler([0.0] * 64))
    generator = _NeverFinish(client, min_commands=3)
    service = AIBridgeService(
        _settings(
            session_secret=session_secret,
            encryption_key_b64=encryption_key_b64,
            embedding_timeout_s=0.05,
        ),
        client=client,
        audit_log=audit,  # type: ignore[arg-type]
        embedding_generator=generator,
    )
    session = _make_session(n_commands=5)
    try:
        task = service.schedule_embedding_generation(session.snapshot())
        assert task is not None
        await task
    finally:
        await service.aclose()

    failed = [e for e in audit.events if e[0] == "bridge.embedding_failed"]
    assert len(failed) == 1
    assert failed[0][1]["error_type"] == "TimeoutError"


async def test_schedule_returns_none_when_generator_not_wired(
    session_secret: str,
    encryption_key_b64: str,
) -> None:
    service = AIBridgeService(
        _settings(
            session_secret=session_secret,
            encryption_key_b64=encryption_key_b64,
        ),
        client=_mock_client(_embed_response_handler([0.0] * 64)),
    )
    session = _make_session()
    try:
        task = service.schedule_embedding_generation(session.snapshot())
    finally:
        await service.aclose()
    assert task is None


async def test_schedule_returns_none_when_embedding_disabled(
    session_secret: str,
    encryption_key_b64: str,
) -> None:
    client = _mock_client(_embed_response_handler([0.0] * 64))
    generator = EmbeddingGenerator(client)
    service = AIBridgeService(
        _settings(
            session_secret=session_secret,
            encryption_key_b64=encryption_key_b64,
            embedding_enabled=False,
        ),
        client=client,
        embedding_generator=generator,
    )
    session = _make_session()
    try:
        task = service.schedule_embedding_generation(session.snapshot())
    finally:
        await service.aclose()
    assert task is None


# ---------------------------------------------------------------------------
# Bridge HTTP DELETE path schedules both intent + embedding
# ---------------------------------------------------------------------------


def test_delete_endpoint_schedules_embedding_generation(
    settings: AnglerfishSettings,
) -> None:
    """End-to-end through the HTTP server: DELETE fires the embedding task."""
    from fastapi.testclient import TestClient

    from anglerfish.bridge import create_bridge_app

    audit_events: list[tuple[str, dict[str, object]]] = []

    class _AuditCapture:
        def record(self, event_type: str, **fields: object) -> None:
            audit_events.append((event_type, fields))

    vector = [0.01 * i for i in range(64)]
    ai = _mock_client(_embed_response_handler(vector))
    generator = EmbeddingGenerator(ai, min_commands=0)
    service = AIBridgeService(
        settings,
        client=ai,
        audit_log=_AuditCapture(),  # type: ignore[arg-type]
        embedding_generator=generator,
    )
    app = create_bridge_app(service)
    with TestClient(app) as c:
        sid = c.post(
            "/api/v1/session",
            json={"source_ip": "1.1.1.1", "username": "root"},
        ).json()["session_id"]
        delete_resp = c.delete(f"/api/v1/session/{sid}")
        assert delete_resp.status_code == 204

    # The TestClient context-manager exit awaits outstanding tasks via
    # the lifespan; once it returns, the embedding audit must be in.
    events = [e for e in audit_events if e[0] == "bridge.embedding_generated"]
    assert len(events) == 1
    assert events[0][1]["session_id"] == sid


# ---------------------------------------------------------------------------
# Quick sanity: SessionEmbedding payload from audit can be re-parsed
# ---------------------------------------------------------------------------


def test_audit_payload_round_trips_to_session_embedding() -> None:
    """The bridge writes vector+dimension+model+generated_at as audit fields.

    The tailer parses those back into a :class:`SessionEmbedding`; the
    payload shape must be lossless.
    """
    sid = uuid4()
    vector = tuple(0.01 * i for i in range(64))
    original = SessionEmbedding(
        session_id=sid,
        vector=vector,
        dimension=64,
        model="embed-test",
        generated_at=datetime(2026, 5, 26, 12, 0, tzinfo=UTC),
    )
    # Emulate what _record_embedding_generated writes to the audit log:
    audit_fields: dict[str, object] = {
        "session_id": str(original.session_id),
        "dimension": original.dimension,
        "model": original.model,
        "vector": list(original.vector),
        "generated_at": original.generated_at.isoformat(),
    }
    serialised = json.loads(json.dumps(audit_fields))
    rebuilt = SessionEmbedding(
        session_id=sid,
        vector=tuple(float(v) for v in serialised["vector"]),
        dimension=serialised["dimension"],
        model=serialised["model"],
        generated_at=datetime.fromisoformat(serialised["generated_at"]),
    )
    assert rebuilt.dimension == original.dimension
    assert rebuilt.model == original.model
    assert rebuilt.generated_at == original.generated_at
    for orig, back in zip(original.vector, rebuilt.vector, strict=True):
        assert abs(orig - back) < 1e-9
