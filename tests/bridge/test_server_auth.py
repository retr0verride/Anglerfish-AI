"""Tests for the bridge HTTP server's bearer-token + protocol-version middleware."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr

from anglerfish.bridge import AIBridgeService, OllamaClient, create_bridge_app
from anglerfish.bridge.server import PROTOCOL_VERSION, SUPPORTED_PROTOCOLS
from anglerfish.config import AnglerfishSettings
from anglerfish.config.models import (
    BridgeConfig,
    CredentialsConfig,
    DashboardConfig,
    OllamaConfig,
)


def _mock_ollama() -> OllamaClient:
    transport = httpx.MockTransport(
        lambda _r: httpx.Response(200, json={"message": {"content": "ok"}}),
    )
    http = httpx.AsyncClient(base_url="http://127.0.0.1:11434", transport=transport)
    return OllamaClient(OllamaConfig(), http_client=http)


def _settings(
    *,
    secret: str | None,
    session_secret: str,
    encryption_key_b64: str,
) -> AnglerfishSettings:
    bridge_cfg: dict[str, Any] = {}
    if secret is not None:
        bridge_cfg["shared_secret"] = SecretStr(secret)
    return AnglerfishSettings(
        dashboard=DashboardConfig(session_secret=SecretStr(session_secret)),
        credentials=CredentialsConfig(encryption_key=SecretStr(encryption_key_b64)),
        bridge=BridgeConfig(**bridge_cfg),
    )


@pytest.fixture
def authed_client(
    session_secret: str,
    encryption_key_b64: str,
) -> Iterator[TestClient]:
    settings = _settings(
        secret="shared-secret-value",
        session_secret=session_secret,
        encryption_key_b64=encryption_key_b64,
    )
    service = AIBridgeService(settings, client=_mock_ollama())
    with TestClient(create_bridge_app(service)) as c:
        yield c


@pytest.fixture
def open_client(
    session_secret: str,
    encryption_key_b64: str,
) -> Iterator[TestClient]:
    settings = _settings(
        secret=None,
        session_secret=session_secret,
        encryption_key_b64=encryption_key_b64,
    )
    service = AIBridgeService(settings, client=_mock_ollama())
    with TestClient(create_bridge_app(service)) as c:
        yield c


def test_health_is_open_even_with_secret(authed_client: TestClient) -> None:
    r = authed_client.get("/api/health")
    assert r.status_code == 200


def test_request_without_bearer_is_401(authed_client: TestClient) -> None:
    r = authed_client.post(
        "/api/v1/session",
        json={"source_ip": "1.1.1.1", "username": "root"},
    )
    assert r.status_code == 401
    assert "bearer" in r.json()["detail"].lower()


def test_request_with_wrong_bearer_is_401(authed_client: TestClient) -> None:
    r = authed_client.post(
        "/api/v1/session",
        json={"source_ip": "1.1.1.1", "username": "root"},
        headers={"Authorization": "Bearer not-the-secret"},
    )
    assert r.status_code == 401


def test_request_with_correct_bearer_succeeds(authed_client: TestClient) -> None:
    r = authed_client.post(
        "/api/v1/session",
        json={"source_ip": "1.1.1.1", "username": "root"},
        headers={"Authorization": "Bearer shared-secret-value"},
    )
    assert r.status_code == 200


def test_protocol_mismatch_is_426(authed_client: TestClient) -> None:
    r = authed_client.post(
        "/api/v1/session",
        json={"source_ip": "1.1.1.1", "username": "root"},
        headers={
            "Authorization": "Bearer shared-secret-value",
            "X-Anglerfish-Protocol": "999",
        },
    )
    assert r.status_code == 426
    body = r.json()
    assert "999" in body["detail"]
    # 426 response lists the supported versions so a misconfigured
    # client can self-correct without reading the source.
    assert "2" in body["detail"]


@pytest.mark.parametrize("version", sorted(SUPPORTED_PROTOCOLS))
def test_every_supported_protocol_passes(
    authed_client: TestClient,
    version: str,
) -> None:
    r = authed_client.post(
        "/api/v1/session",
        json={"source_ip": "1.1.1.1", "username": "root"},
        headers={
            "Authorization": "Bearer shared-secret-value",
            "X-Anglerfish-Protocol": version,
        },
    )
    assert r.status_code == 200


def test_matching_protocol_passes(authed_client: TestClient) -> None:
    r = authed_client.post(
        "/api/v1/session",
        json={"source_ip": "1.1.1.1", "username": "root"},
        headers={
            "Authorization": "Bearer shared-secret-value",
            "X-Anglerfish-Protocol": PROTOCOL_VERSION,
        },
    )
    assert r.status_code == 200


def test_no_secret_configured_means_no_auth_check(open_client: TestClient) -> None:
    r = open_client.post(
        "/api/v1/session",
        json={"source_ip": "1.1.1.1", "username": "root"},
    )
    # No Authorization header, no shared_secret in config → permissive.
    assert r.status_code == 200


def test_protocol_version_constant() -> None:
    # Stage 2A bumped to "2" to add CommandRequest.fs_context.
    # Protocol "1" (the Cowrie shim's version) was dropped from
    # SUPPORTED_PROTOCOLS alongside the 2026-05 Cowrie removal.
    assert PROTOCOL_VERSION == "2"
    assert PROTOCOL_VERSION in SUPPORTED_PROTOCOLS


def test_legacy_protocol_v1_is_rejected() -> None:
    """The Cowrie shim's v1 acceptance was removed in 2026-05."""
    assert "1" not in SUPPORTED_PROTOCOLS
    assert frozenset({"2"}) == SUPPORTED_PROTOCOLS
