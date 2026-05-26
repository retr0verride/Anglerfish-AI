"""Bridge-side integration tests for Stage 7 slice 2 intent extraction."""

from __future__ import annotations

import asyncio
import json
from collections.abc import Callable
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
from anglerfish.intel import IntentExtractor
from anglerfish.models import ResponseSource, ThreatAssessment, ThreatTechnique

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
    intent_enabled: bool = True,
    intent_timeout_s: float = 60.0,
) -> AnglerfishSettings:
    return AnglerfishSettings(
        dashboard=DashboardConfig(session_secret=SecretStr(session_secret)),
        credentials=CredentialsConfig(encryption_key=SecretStr(encryption_key_b64)),
        bridge=BridgeConfig(
            intent_extraction_enabled=intent_enabled,
            intent_extraction_timeout_s=intent_timeout_s,
        ),
    )


def _structured_payload_handler(payload: dict[str, object]) -> _Handler:
    def handler(_req: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "message": {"content": json.dumps(payload)},
                "done": True,
                "prompt_eval_count": 100,
                "eval_count": 50,
            },
        )

    return handler


# ---------------------------------------------------------------------------
# Schedule + run
# ---------------------------------------------------------------------------


async def test_schedule_intent_extraction_audits_on_success(
    session_secret: str,
    encryption_key_b64: str,
) -> None:
    audit = _MockAudit()
    handler = _structured_payload_handler(
        {
            "actor_profile": "automated",
            "intent": "Deploy cryptominer.",
            "why": "Downloaded miner; configured pool.",
            "matched_techniques": ["T1496"],
            "confidence": "high",
            "summary": "Automated cryptomining session.",
        },
    )
    client = _mock_client(handler)
    extractor = IntentExtractor(client, min_commands=3)
    service = AIBridgeService(
        _settings(
            session_secret=session_secret,
            encryption_key_b64=encryption_key_b64,
        ),
        client=client,
        audit_log=audit,  # type: ignore[arg-type]
        intent_extractor=extractor,
    )
    session = _make_session(n_commands=5)
    try:
        task = service.schedule_intent_extraction(session.snapshot())
        assert task is not None
        await task
    finally:
        await service.aclose()

    events = [e for e in audit.events if e[0] == "bridge.intent_extracted"]
    assert len(events) == 1
    _, fields = events[0]
    assert fields["session_id"] == str(session.session_id)
    assert fields["actor_profile"] == "automated"
    assert fields["confidence"] == "high"
    assert fields["matched_techniques"] == ["T1496"]


async def test_schedule_intent_extraction_audits_on_llm_failure(
    session_secret: str,
    encryption_key_b64: str,
) -> None:
    """LLM 5xx -> intent_extraction_failed (never raises to background loop)."""
    audit = _MockAudit()

    def handler(_req: httpx.Request) -> httpx.Response:
        return httpx.Response(503, text="overloaded")

    client = _mock_client(handler)
    extractor = IntentExtractor(client, min_commands=3)
    service = AIBridgeService(
        _settings(
            session_secret=session_secret,
            encryption_key_b64=encryption_key_b64,
        ),
        client=client,
        audit_log=audit,  # type: ignore[arg-type]
        intent_extractor=extractor,
    )
    session = _make_session(n_commands=5)
    try:
        task = service.schedule_intent_extraction(session.snapshot())
        assert task is not None
        await task  # must not raise
    finally:
        await service.aclose()

    events = [e for e in audit.events if e[0] == "bridge.intent_extraction_failed"]
    assert len(events) == 1
    _, fields = events[0]
    assert fields["error_type"] == "OllamaUnavailableError"
    assert "server error" in str(fields["error"])


async def test_schedule_intent_extraction_audits_on_timeout(
    session_secret: str,
    encryption_key_b64: str,
) -> None:
    """A stuck extractor trips the wall-clock timeout."""
    audit = _MockAudit()

    class _NeverFinish(IntentExtractor):
        async def extract(self, snapshot, threat=None):  # type: ignore[override,no-untyped-def]
            del snapshot, threat
            await asyncio.sleep(10.0)
            raise AssertionError("should not reach")

    client = _mock_client(_structured_payload_handler({}))
    extractor = _NeverFinish(client, min_commands=3)
    service = AIBridgeService(
        _settings(
            session_secret=session_secret,
            encryption_key_b64=encryption_key_b64,
            intent_timeout_s=0.05,
        ),
        client=client,
        audit_log=audit,  # type: ignore[arg-type]
        intent_extractor=extractor,
    )
    session = _make_session(n_commands=5)
    try:
        task = service.schedule_intent_extraction(session.snapshot())
        assert task is not None
        await task
    finally:
        await service.aclose()

    events = [e for e in audit.events if e[0] == "bridge.intent_extraction_failed"]
    assert len(events) == 1
    _, fields = events[0]
    assert fields["error_type"] == "TimeoutError"


async def test_schedule_returns_none_when_extractor_not_wired(
    session_secret: str,
    encryption_key_b64: str,
) -> None:
    service = AIBridgeService(
        _settings(
            session_secret=session_secret,
            encryption_key_b64=encryption_key_b64,
        ),
        client=_mock_client(_structured_payload_handler({})),
    )
    session = _make_session()
    try:
        task = service.schedule_intent_extraction(session.snapshot())
    finally:
        await service.aclose()
    assert task is None


async def test_schedule_returns_none_when_extraction_disabled(
    session_secret: str,
    encryption_key_b64: str,
) -> None:
    client = _mock_client(_structured_payload_handler({}))
    extractor = IntentExtractor(client)
    service = AIBridgeService(
        _settings(
            session_secret=session_secret,
            encryption_key_b64=encryption_key_b64,
            intent_enabled=False,
        ),
        client=client,
        intent_extractor=extractor,
    )
    session = _make_session()
    try:
        task = service.schedule_intent_extraction(session.snapshot())
    finally:
        await service.aclose()
    assert task is None


async def test_threat_assessment_passed_through_to_extractor(
    session_secret: str,
    encryption_key_b64: str,
) -> None:
    """record_threat_assessment is consulted at extraction time."""
    seen_payloads: list[dict[str, object]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen_payloads.append(json.loads(request.read()))
        return httpx.Response(
            200,
            json={
                "message": {
                    "content": json.dumps(
                        {
                            "actor_profile": "opportunistic",
                            "intent": "x",
                            "why": "x",
                            "matched_techniques": [],
                            "confidence": "low",
                            "summary": "x",
                        },
                    ),
                },
                "done": True,
            },
        )

    client = _mock_client(handler)
    extractor = IntentExtractor(client, min_commands=3)
    audit = _MockAudit()
    service = AIBridgeService(
        _settings(
            session_secret=session_secret,
            encryption_key_b64=encryption_key_b64,
        ),
        client=client,
        audit_log=audit,  # type: ignore[arg-type]
        intent_extractor=extractor,
    )
    session = _make_session(n_commands=5)
    threat = ThreatAssessment(
        session_id=session.session_id,
        score=77,
        techniques=(ThreatTechnique(id="T1059.004", name="Unix Shell"),),
        persistence_attempted=False,
        high_severity=True,
        notes=("Cryptomining pattern.",),
    )
    service.record_threat_assessment(session.session_id, threat)
    try:
        task = service.schedule_intent_extraction(session.snapshot())
        assert task is not None
        await task
    finally:
        await service.aclose()

    # The structured_chat payload includes the threat-context system
    # message with the score we recorded.
    system_contents = [m["content"] for m in seen_payloads[0]["messages"] if m["role"] == "system"]
    assert any("Score: 77" in c for c in system_contents)


async def test_end_session_budget_drops_latest_threat(
    session_secret: str,
    encryption_key_b64: str,
) -> None:
    service = AIBridgeService(
        _settings(
            session_secret=session_secret,
            encryption_key_b64=encryption_key_b64,
        ),
        client=_mock_client(_structured_payload_handler({})),
    )
    sid = uuid4()
    threat = ThreatAssessment(
        session_id=sid,
        score=10,
        techniques=(),
        persistence_attempted=False,
        high_severity=False,
        notes=(),
    )
    service.record_threat_assessment(sid, threat)
    service.end_session_budget(sid)
    assert sid not in service._latest_threat
    await service.aclose()


# ---------------------------------------------------------------------------
# Bridge HTTP DELETE path schedules the extraction
# ---------------------------------------------------------------------------


def test_delete_endpoint_schedules_intent_extraction(
    settings: AnglerfishSettings,
) -> None:
    """End-to-end through the HTTP server: DELETE fires the extraction task."""
    from fastapi.testclient import TestClient

    from anglerfish.bridge import create_bridge_app

    audit_events: list[tuple[str, dict[str, object]]] = []

    class _AuditCapture:
        """Drop-in for AuditLog that records events into the outer list."""

        def record(self, event_type: str, **fields: object) -> None:
            audit_events.append((event_type, fields))

    handler = _structured_payload_handler(
        {
            "actor_profile": "opportunistic",
            "intent": "x",
            "why": "x",
            "matched_techniques": [],
            "confidence": "low",
            "summary": "x",
        },
    )
    ai = _mock_client(handler)
    extractor = IntentExtractor(ai, min_commands=0)  # extract even tiny sessions
    service = AIBridgeService(
        settings,
        client=ai,
        audit_log=_AuditCapture(),  # type: ignore[arg-type]
        intent_extractor=extractor,
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
    # the lifespan; once it returns, the extraction audit must be in.
    intent_events = [e for e in audit_events if e[0] == "bridge.intent_extracted"]
    assert len(intent_events) == 1
    assert intent_events[0][1]["session_id"] == sid
