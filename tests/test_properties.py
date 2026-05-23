"""Smoke tests for read-only property getters.

These are uninteresting on their own — they exist to keep the trivial
one-line property bodies from dragging the coverage gate below 90%.
The semantic behaviour each getter exposes is exercised in the
subsystem-specific test modules.
"""

from __future__ import annotations

from uuid import uuid4

import httpx

from anglerfish.bridge.client import OllamaClient
from anglerfish.bridge.rate_limit import BridgeRateLimiter
from anglerfish.bridge.service import AIBridgeService
from anglerfish.config import AnglerfishSettings
from anglerfish.config.models import OllamaConfig, RateLimitConfig


def test_ollama_client_config_property() -> None:
    cfg = OllamaConfig()
    transport = httpx.MockTransport(
        lambda _r: httpx.Response(200, json={"message": {"content": ""}}),
    )
    http = httpx.AsyncClient(base_url="http://127.0.0.1:11434", transport=transport)
    client = OllamaClient(cfg, http_client=http)
    assert client.config is cfg


def test_rate_limiter_config_property() -> None:
    cfg = RateLimitConfig()
    limiter = BridgeRateLimiter(cfg)
    assert limiter.config is cfg


def test_service_property_getters(settings: AnglerfishSettings) -> None:
    transport = httpx.MockTransport(
        lambda _r: httpx.Response(200, json={"message": {"content": ""}}),
    )
    http = httpx.AsyncClient(base_url="http://127.0.0.1:11434", transport=transport)
    client = OllamaClient(settings.ollama, http_client=http)
    service = AIBridgeService(settings, client=client)
    assert service.settings is settings
    assert service.client is client
    assert isinstance(service.limiter, BridgeRateLimiter)


def test_rate_limiter_active_session_count_starts_zero() -> None:
    limiter = BridgeRateLimiter(RateLimitConfig())
    assert limiter.active_session_count() == 0
    assert uuid4() not in limiter._buckets
