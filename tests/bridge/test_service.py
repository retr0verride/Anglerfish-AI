"""Tests for :class:`anglerfish.bridge.AIBridgeService`."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from uuid import uuid4

import httpx
import pytest
from pydantic import SecretStr

from anglerfish.bridge.client import OllamaClient
from anglerfish.bridge.rate_limit import BridgeRateLimiter
from anglerfish.bridge.service import AIBridgeService
from anglerfish.bridge.session import SessionContext
from anglerfish.config import AnglerfishSettings
from anglerfish.config.models import (
    BridgeConfig,
    CredentialsConfig,
    DashboardConfig,
    OllamaConfig,
    RateLimitConfig,
)
from anglerfish.models.session import ResponseSource


def _mock_ollama_client(
    handler: Callable[[httpx.Request], httpx.Response],
) -> OllamaClient:
    transport = httpx.MockTransport(handler)
    http = httpx.AsyncClient(base_url="http://127.0.0.1:11434", transport=transport)
    return OllamaClient(OllamaConfig(), http_client=http)


def _make_session(history_window: int = 20) -> SessionContext:
    return SessionContext(
        uuid4(),
        source_ip="203.0.113.7",
        username="root",
        fake_hostname="srv-prod-01",
        fake_username="root",
        fake_cwd="/root",
        history_window=history_window,
    )


# ---------------------------------------------------------------------------
# Happy-path AI response
# ---------------------------------------------------------------------------


async def test_handle_command_via_ai(settings: AnglerfishSettings) -> None:
    seen_requests: list[bytes] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen_requests.append(request.read())
        return httpx.Response(
            200,
            json={"message": {"role": "assistant", "content": "passwd  shadow  hosts"}},
        )

    service = AIBridgeService(settings, client=_mock_ollama_client(handler))
    session = _make_session()
    try:
        response = await service.handle_command(session, "ls /etc")
    finally:
        await service.aclose()
    assert response.source == ResponseSource.AI
    assert response.text == "passwd  shadow  hosts"
    assert session.history()[-1].command == "ls /etc"
    assert len(seen_requests) == 1
    assert b"ls /etc" in seen_requests[0]


# ---------------------------------------------------------------------------
# cd is handled deterministically — no Ollama call
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("command", "expected_cwd"),
    [
        ("cd /etc", "/etc"),
        ("cd /etc/", "/etc"),
        ("cd /var/log", "/var/log"),
        ("cd subdir", "/root/subdir"),
        ("cd .", "/root"),
        ("cd ..", "/"),
    ],
)
async def test_cd_handled_locally(
    settings: AnglerfishSettings,
    command: str,
    expected_cwd: str,
) -> None:
    called = False

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal called
        called = True
        return httpx.Response(500)

    service = AIBridgeService(settings, client=_mock_ollama_client(handler))
    session = _make_session()
    try:
        response = await service.handle_command(session, command)
    finally:
        await service.aclose()
    assert called is False
    assert response.text == ""
    assert session.cwd == expected_cwd


async def test_cd_bare_goes_home_for_root(settings: AnglerfishSettings) -> None:
    service = AIBridgeService(
        settings,
        client=_mock_ollama_client(lambda _r: httpx.Response(500)),
    )
    session = _make_session()
    try:
        await service.handle_command(session, "cd")
    finally:
        await service.aclose()
    assert session.cwd == "/root"


async def test_cd_tilde_goes_home_for_non_root(
    session_secret: str,
    encryption_key_b64: str,
) -> None:
    settings = AnglerfishSettings(
        dashboard=DashboardConfig(session_secret=SecretStr(session_secret)),
        credentials=CredentialsConfig(encryption_key=SecretStr(encryption_key_b64)),
        bridge=BridgeConfig(fake_username="alice", fake_cwd="/home/alice"),
    )
    service = AIBridgeService(
        settings,
        client=_mock_ollama_client(lambda _r: httpx.Response(500)),
    )
    session = SessionContext(
        uuid4(),
        source_ip="1.2.3.4",
        username="alice",
        fake_hostname="srv-prod-01",
        fake_username="alice",
        fake_cwd="/home/alice",
        history_window=10,
    )
    try:
        await service.handle_command(session, "cd ~")
        assert session.cwd == "/home/alice"
        await service.handle_command(session, "cd /tmp")
        assert session.cwd == "/tmp"
        await service.handle_command(session, "cd ..")
        assert session.cwd == "/"
    finally:
        await service.aclose()


# ---------------------------------------------------------------------------
# Empty / blank commands short-circuit
# ---------------------------------------------------------------------------


async def test_empty_command_skips_ollama(settings: AnglerfishSettings) -> None:
    called = False

    def handler(_r: httpx.Request) -> httpx.Response:
        nonlocal called
        called = True
        return httpx.Response(200, json={"message": {"content": ""}})

    service = AIBridgeService(settings, client=_mock_ollama_client(handler))
    session = _make_session()
    try:
        response = await service.handle_command(session, "   \t  ")
    finally:
        await service.aclose()
    assert called is False
    assert response.text == ""
    assert response.source == ResponseSource.AI


# ---------------------------------------------------------------------------
# Failure modes degrade to fallback
# ---------------------------------------------------------------------------


async def test_ollama_failure_uses_scripted_fallback(
    settings: AnglerfishSettings,
) -> None:
    def handler(_r: httpx.Request) -> httpx.Response:
        return httpx.Response(503, text="unavailable")

    service = AIBridgeService(settings, client=_mock_ollama_client(handler))
    session = _make_session()
    try:
        response = await service.handle_command(session, "whoami")
    finally:
        await service.aclose()
    assert response.source == ResponseSource.FALLBACK
    assert response.text == "root"


async def test_ollama_failure_unknown_command_returns_command_not_found(
    settings: AnglerfishSettings,
) -> None:
    def handler(_r: httpx.Request) -> httpx.Response:
        return httpx.Response(503)

    service = AIBridgeService(settings, client=_mock_ollama_client(handler))
    session = _make_session()
    try:
        response = await service.handle_command(session, "supersecrettool")
    finally:
        await service.aclose()
    assert response.source == ResponseSource.FALLBACK
    assert response.text == "bash: supersecrettool: command not found"


async def test_fallback_disabled_returns_rejected(
    session_secret: str,
    encryption_key_b64: str,
) -> None:
    settings = AnglerfishSettings(
        dashboard=DashboardConfig(session_secret=SecretStr(session_secret)),
        credentials=CredentialsConfig(encryption_key=SecretStr(encryption_key_b64)),
        bridge=BridgeConfig(enable_fallback=False),
    )

    def handler(_r: httpx.Request) -> httpx.Response:
        return httpx.Response(503)

    service = AIBridgeService(settings, client=_mock_ollama_client(handler))
    session = _make_session()
    try:
        response = await service.handle_command(session, "whoami")
    finally:
        await service.aclose()
    assert response.source == ResponseSource.REJECTED
    assert response.text == ""


async def test_session_rate_limited_falls_back(settings: AnglerfishSettings) -> None:
    """When the per-session bucket is empty, the bridge degrades to scripted."""

    def handler(_r: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"message": {"content": "ai-out"}})

    rate_cfg = RateLimitConfig(
        max_concurrent_requests=4,
        requests_per_session_per_minute=1,
        session_burst=1,
        queue_timeout_s=1.0,
        bucket_idle_eviction_s=300.0,
    )
    limiter = BridgeRateLimiter(rate_cfg)
    service = AIBridgeService(
        settings,
        client=_mock_ollama_client(handler),
        limiter=limiter,
    )
    session = _make_session()
    try:
        first = await service.handle_command(session, "whoami")
        second = await service.handle_command(session, "whoami")
    finally:
        await service.aclose()
    assert first.source == ResponseSource.AI
    assert second.source == ResponseSource.FALLBACK


async def test_global_queue_timeout_falls_back_to_scripted(
    settings: AnglerfishSettings,
) -> None:
    """A saturated global semaphore must trip the queue-timeout fallback path."""
    rate_cfg = RateLimitConfig(
        max_concurrent_requests=1,
        requests_per_session_per_minute=600,
        session_burst=100,
        queue_timeout_s=0.05,
        bucket_idle_eviction_s=300.0,
    )
    limiter = BridgeRateLimiter(rate_cfg)

    sid_holder = uuid4()
    started = asyncio.Event()
    release = asyncio.Event()

    async def hold_slot() -> None:
        async with limiter.slot(sid_holder):
            started.set()
            await release.wait()

    holder_task = asyncio.create_task(hold_slot())
    try:
        await asyncio.wait_for(started.wait(), timeout=1.0)

        def handler(_r: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"message": {"content": "x"}})

        service = AIBridgeService(
            settings,
            client=_mock_ollama_client(handler),
            limiter=limiter,
        )
        session = _make_session()
        try:
            response = await service.handle_command(session, "whoami")
        finally:
            await service.aclose()
        assert response.source == ResponseSource.FALLBACK
        assert response.text == "root"
    finally:
        release.set()
        await holder_task


async def test_quote_imbalance_handled_gracefully(
    settings: AnglerfishSettings,
) -> None:
    """Commands that fail shlex parsing must not crash the bridge."""

    def handler(_r: httpx.Request) -> httpx.Response:
        return httpx.Response(503)

    service = AIBridgeService(settings, client=_mock_ollama_client(handler))
    session = _make_session()
    try:
        response = await service.handle_command(session, 'echo "unterminated')
    finally:
        await service.aclose()
    assert response.source == ResponseSource.FALLBACK
    assert response.text.startswith("bash: ")


async def test_quote_imbalance_in_cd_branch(
    settings: AnglerfishSettings,
) -> None:
    """A shlex parse error must NOT be treated as cd handling."""

    def handler(_r: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"message": {"content": "ok"}})

    service = AIBridgeService(settings, client=_mock_ollama_client(handler))
    session = _make_session()
    try:
        response = await service.handle_command(session, 'cd "unterminated')
    finally:
        await service.aclose()
    # shlex fails → _handle_cd returns False → AI path is taken.
    assert response.source == ResponseSource.AI
    assert session.cwd == "/root"


# ---------------------------------------------------------------------------
# Output is capped
# ---------------------------------------------------------------------------


async def test_response_capped_at_ollama_max(settings: AnglerfishSettings) -> None:
    huge = "x" * (settings.ollama.max_response_chars + 100)

    def handler(_r: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"message": {"content": huge}})

    service = AIBridgeService(settings, client=_mock_ollama_client(handler))
    session = _make_session()
    try:
        response = await service.handle_command(session, "yes")
    finally:
        await service.aclose()
    assert len(response.text) <= settings.ollama.max_response_chars


# ---------------------------------------------------------------------------
# Static helpers
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("inp", "out"),
    [
        ("/etc", "/etc"),
        ("/etc/", "/etc"),
        ("/etc/./foo", "/etc/foo"),
        ("/etc/../var", "/var"),
        ("/etc/foo/../bar", "/etc/bar"),
        ("relative", "/relative"),
        ("/", "/"),
        ("/..", "/"),
    ],
)
def test_normalise_path(inp: str, out: str) -> None:
    assert AIBridgeService._normalise_path(inp) == out


@pytest.mark.parametrize(
    ("inp", "out"),
    [
        ("", ""),
        ("ls", "ls"),
        ("ls -la", "ls"),
        ('echo "unterminated', "echo"),
    ],
)
def test_first_token(inp: str, out: str) -> None:
    assert AIBridgeService._first_token(inp) == out


# ---------------------------------------------------------------------------
# Async context manager support
# ---------------------------------------------------------------------------


async def test_service_async_context_manager(settings: AnglerfishSettings) -> None:
    closed: list[bool] = []

    class _Tracking(httpx.AsyncClient):
        async def aclose(self) -> None:
            closed.append(True)
            await super().aclose()

    tracking = _Tracking(
        transport=httpx.MockTransport(
            lambda _r: httpx.Response(200, json={"message": {"content": "ok"}}),
        ),
        base_url="http://127.0.0.1:11434",
    )
    # OllamaClient with an injected client doesn't own it, so it won't close it.
    client = OllamaClient(OllamaConfig(), http_client=tracking)
    async with AIBridgeService(settings, client=client) as service:
        response = await service.handle_command(_make_session(), "whoami")
    assert response.source == ResponseSource.AI
    await tracking.aclose()
    assert closed == [True]
