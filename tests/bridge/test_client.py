"""Tests for :class:`anglerfish.bridge.OllamaClient`."""

from __future__ import annotations

from typing import Any

import httpx
import pytest

from anglerfish.bridge.client import ChatMessage, OllamaClient
from anglerfish.bridge.errors import OllamaResponseError, OllamaUnavailableError
from anglerfish.config.models import OllamaConfig


def _mock_client(
    handler: httpx.MockTransport | None = None,
    *,
    response_factory: Any = None,
) -> httpx.AsyncClient:
    if handler is None:
        assert response_factory is not None

        def _wrap(request: httpx.Request) -> httpx.Response:
            response: httpx.Response = response_factory(request)
            return response

        handler = httpx.MockTransport(_wrap)
    return httpx.AsyncClient(
        base_url="http://127.0.0.1:11434",
        transport=handler,
    )


async def test_chat_returns_assistant_content() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/api/chat"
        body = request.read()
        assert b"deepseek-coder" in body
        return httpx.Response(
            200,
            json={
                "model": "deepseek-coder:6.7b",
                "message": {"role": "assistant", "content": "drwxr-xr-x 2 root root 4096"},
                "done": True,
            },
        )

    client = OllamaClient(
        OllamaConfig(),
        http_client=_mock_client(httpx.MockTransport(handler)),
    )
    try:
        result = await client.chat([ChatMessage(role="user", content="ls /etc")])
    finally:
        await client.aclose()
    assert result == "drwxr-xr-x 2 root root 4096"


async def test_chat_5xx_is_unavailable() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503, text="overloaded")

    client = OllamaClient(
        OllamaConfig(),
        http_client=_mock_client(httpx.MockTransport(handler)),
    )
    with pytest.raises(OllamaUnavailableError):
        await client.chat([ChatMessage(role="user", content="x")])
    await client.aclose()


async def test_chat_4xx_is_response_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(400, text="bad request")

    client = OllamaClient(
        OllamaConfig(),
        http_client=_mock_client(httpx.MockTransport(handler)),
    )
    with pytest.raises(OllamaResponseError):
        await client.chat([ChatMessage(role="user", content="x")])
    await client.aclose()


async def test_chat_network_failure_is_unavailable() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    client = OllamaClient(
        OllamaConfig(),
        http_client=_mock_client(httpx.MockTransport(handler)),
    )
    with pytest.raises(OllamaUnavailableError):
        await client.chat([ChatMessage(role="user", content="x")])
    await client.aclose()


async def test_chat_invalid_json_is_response_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="not json")

    client = OllamaClient(
        OllamaConfig(),
        http_client=_mock_client(httpx.MockTransport(handler)),
    )
    with pytest.raises(OllamaResponseError):
        await client.chat([ChatMessage(role="user", content="x")])
    await client.aclose()


async def test_chat_missing_message_field_is_response_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"done": True})

    client = OllamaClient(
        OllamaConfig(),
        http_client=_mock_client(httpx.MockTransport(handler)),
    )
    with pytest.raises(OllamaResponseError):
        await client.chat([ChatMessage(role="user", content="x")])
    await client.aclose()


async def test_chat_non_string_content_is_response_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"message": {"content": 42}})

    client = OllamaClient(
        OllamaConfig(),
        http_client=_mock_client(httpx.MockTransport(handler)),
    )
    with pytest.raises(OllamaResponseError):
        await client.chat([ChatMessage(role="user", content="x")])
    await client.aclose()


async def test_chat_non_object_response_is_response_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=[1, 2, 3])

    client = OllamaClient(
        OllamaConfig(),
        http_client=_mock_client(httpx.MockTransport(handler)),
    )
    with pytest.raises(OllamaResponseError):
        await client.chat([ChatMessage(role="user", content="x")])
    await client.aclose()


async def test_async_context_manager_closes_owned_client() -> None:
    closed: list[bool] = []

    class _Tracking(httpx.AsyncClient):
        async def aclose(self) -> None:
            closed.append(True)
            await super().aclose()

    transport = httpx.MockTransport(
        lambda _req: httpx.Response(200, json={"message": {"content": "ok"}}),
    )
    tracking = _Tracking(transport=transport, base_url="http://127.0.0.1:11434")
    client = OllamaClient(OllamaConfig(), http_client=tracking)
    async with client:
        result = await client.chat([ChatMessage(role="user", content="x")])
    assert result == "ok"
    # We did NOT own the injected client, so aclose() should not have been called.
    assert closed == []
    # Caller still has to close their injected client.
    await tracking.aclose()
    assert closed == [True]


async def test_client_creates_own_transport_when_none_provided(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    created: list[httpx.AsyncClient] = []

    original = httpx.AsyncClient

    class _Spy(original):  # type: ignore[misc, valid-type]
        def __init__(self, *args: object, **kwargs: object) -> None:
            super().__init__(*args, **kwargs)
            created.append(self)

    monkeypatch.setattr("anglerfish.bridge.client.httpx.AsyncClient", _Spy)
    client = OllamaClient(OllamaConfig())
    assert len(created) == 1
    await client.aclose()


def test_chat_message_is_frozen() -> None:
    from pydantic import ValidationError

    m = ChatMessage(role="user", content="hi")
    with pytest.raises(ValidationError):
        m.content = "other"  # type: ignore[misc]
