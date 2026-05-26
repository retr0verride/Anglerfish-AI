"""Bridge-side integration tests for Stage 9 slice 9.2 persona selection."""

from __future__ import annotations

from collections.abc import Callable, Iterator
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr

from anglerfish.bridge import AIBridgeService, OllamaClient, create_bridge_app
from anglerfish.bridge.prompts import build_system_prompt
from anglerfish.config import (
    AnglerfishSettings,
    BridgeConfig,
    CredentialsConfig,
    DashboardConfig,
)
from anglerfish.config.models import OllamaConfig, PersonaConfig, SessionStoreConfig
from anglerfish.persona import PersonaRegistry, PersonaSelector
from anglerfish.persona.schema import Persona
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


def _persona(name: str, hostname: str | None = None) -> Persona:
    return Persona(
        name=name,
        description=f"The {name} persona.",
        hostname=hostname or name,
        username="root",
        cwd="/root",
        prompt_block=f"PROMPT-BLOCK-FOR-{name.upper()}",
    )


@pytest.fixture
def persona_registry() -> PersonaRegistry:
    return PersonaRegistry(
        {
            "forgotten-debian-box": _persona(
                "forgotten-debian-box",
                hostname="srv-prod-01",
            ),
            "gpu-rig": _persona("gpu-rig", hostname="gpu-rig-04"),
            "dev-laptop": _persona("dev-laptop", hostname="lappy"),
        },
    )


@pytest.fixture
async def reader(tmp_path: Path) -> Iterator[SessionStoreReader]:
    """Migrate the DB via a writer, then open + yield a read-only handle."""
    config = SessionStoreConfig(database_path=tmp_path / "sessions.db")
    writer = SessionStore(config)
    await writer.open()
    try:
        r = SessionStoreReader(config)
        await r.open()
        try:
            yield r
        finally:
            await r.aclose()
    finally:
        await writer.aclose()


def _settings(
    *,
    session_secret: str,
    encryption_key_b64: str,
    sessions_db: Path,
    persona_enabled: bool = True,
) -> AnglerfishSettings:
    return AnglerfishSettings(
        dashboard=DashboardConfig(session_secret=SecretStr(session_secret)),
        credentials=CredentialsConfig(encryption_key=SecretStr(encryption_key_b64)),
        bridge=BridgeConfig(),
        sessions=SessionStoreConfig(database_path=sessions_db),
        persona=PersonaConfig(enabled=persona_enabled),
    )


# ---------------------------------------------------------------------------
# build_system_prompt: persona prompt_block lands in the prompt
# ---------------------------------------------------------------------------


def test_build_system_prompt_includes_persona_block() -> None:
    persona = _persona("gpu-rig", hostname="gpu-rig-04")
    prompt = build_system_prompt(BridgeConfig(), cwd="/root", persona=persona)
    assert "gpu-rig-04" in prompt
    assert "PROMPT-BLOCK-FOR-GPU-RIG" in prompt


def test_build_system_prompt_without_persona_uses_bridge_config_defaults() -> None:
    prompt = build_system_prompt(BridgeConfig(), cwd="/root", persona=None)
    # Default BridgeConfig.fake_hostname is "srv-prod-01".
    assert "srv-prod-01" in prompt
    # No persona block markers should appear when persona is None.
    assert "PROMPT-BLOCK" not in prompt


# ---------------------------------------------------------------------------
# select_persona on the service
# ---------------------------------------------------------------------------


async def test_select_persona_returns_none_when_disabled(
    session_secret: str,
    encryption_key_b64: str,
    tmp_path: Path,
    reader: SessionStoreReader,
    persona_registry: PersonaRegistry,
) -> None:
    settings = _settings(
        session_secret=session_secret,
        encryption_key_b64=encryption_key_b64,
        sessions_db=tmp_path / "sessions.db",
        persona_enabled=False,
    )
    service = AIBridgeService(
        settings,
        client=_mock_client(),
        persona_selector=PersonaSelector(persona_registry, reader),
    )
    try:
        result = await service.select_persona("203.0.113.7")
    finally:
        await service.aclose()
    assert result is None


async def test_select_persona_returns_none_when_no_selector(
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
        result = await service.select_persona("203.0.113.7")
    finally:
        await service.aclose()
    assert result is None


async def test_select_persona_calls_through_to_selector(
    session_secret: str,
    encryption_key_b64: str,
    tmp_path: Path,
    reader: SessionStoreReader,
    persona_registry: PersonaRegistry,
) -> None:
    settings = _settings(
        session_secret=session_secret,
        encryption_key_b64=encryption_key_b64,
        sessions_db=tmp_path / "sessions.db",
    )
    service = AIBridgeService(
        settings,
        client=_mock_client(),
        persona_selector=PersonaSelector(persona_registry, reader),
    )
    try:
        result = await service.select_persona("203.0.113.7")
    finally:
        await service.aclose()
    assert result is not None
    # First-time IP -> hash fallback path; persona must come from registry.
    assert result.persona.name in persona_registry.names()
    assert result.reason == "hash_fallback"


# ---------------------------------------------------------------------------
# HTTP POST /api/v1/session end-to-end with selector wired
# ---------------------------------------------------------------------------


def test_post_session_audits_persona_selected(
    session_secret: str,
    encryption_key_b64: str,
    tmp_path: Path,
    persona_registry: PersonaRegistry,
) -> None:
    """End-to-end through the bridge HTTP endpoint."""
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
    reader_local = SessionStoreReader(settings.sessions)
    selector = PersonaSelector(persona_registry, reader_local)
    service = AIBridgeService(
        settings,
        client=_mock_client(),
        audit_log=audit,  # type: ignore[arg-type]
        persona_selector=selector,
    )

    async def _open_reader() -> None:
        await reader_local.open()

    asyncio.run(_open_reader())

    app = create_bridge_app(service)
    with TestClient(app) as c:
        body = c.post(
            "/api/v1/session",
            json={"source_ip": "203.0.113.55", "username": "root"},
        ).json()
        sid = body["session_id"]

    selected = [e for e in audit.events if e[0] == "bridge.persona_selected"]
    assert len(selected) == 1
    _, fields = selected[0]
    assert fields["session_id"] == sid
    assert fields["source_ip"] == "203.0.113.55"
    assert fields["persona"] in persona_registry.names()
    assert fields["selection_reason"] == "hash_fallback"
    # The endpoint response reflects the persona's identity.
    assert body["fake_hostname"] in {
        p.hostname for p in [persona_registry.get(name) for name in persona_registry.names()]
    }


def test_post_session_no_persona_audit_when_disabled(
    session_secret: str,
    encryption_key_b64: str,
    tmp_path: Path,
) -> None:
    """Selector absent -> SessionContext falls back to BridgeConfig defaults."""
    settings = _settings(
        session_secret=session_secret,
        encryption_key_b64=encryption_key_b64,
        sessions_db=tmp_path / "sessions.db",
        persona_enabled=False,
    )
    audit = _CaptureAudit()
    service = AIBridgeService(
        settings,
        client=_mock_client(),
        audit_log=audit,  # type: ignore[arg-type]
    )
    app = create_bridge_app(service)
    with TestClient(app) as c:
        body = c.post(
            "/api/v1/session",
            json={"source_ip": "203.0.113.55", "username": "root"},
        ).json()
    assert body["fake_hostname"] == BridgeConfig().fake_hostname
    assert not [e for e in audit.events if e[0] == "bridge.persona_selected"]
