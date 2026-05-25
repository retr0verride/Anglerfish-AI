"""Tests for :meth:`anglerfish.llm.LLMClient.stream_chat` (Stage 5 slice 4)."""

from __future__ import annotations

import json
from collections.abc import AsyncIterator, Callable

import httpx
import pytest

from anglerfish.config.models import OllamaConfig
from anglerfish.llm import ChatChunk, ChatMessage, LLMClient, LLMRole
from anglerfish.llm.errors import OllamaResponseError, OllamaUnavailableError

_Handler = Callable[[httpx.Request], httpx.Response]


def _make_client(handler: _Handler) -> LLMClient:
    transport = httpx.MockTransport(handler)
    http_client = httpx.AsyncClient(transport=transport, base_url="http://127.0.0.1:11434")
    return LLMClient(
        OllamaConfig(fast_model="fast:7b", deep_model="deep:14b"),
        http_client=http_client,
    )


def _ndjson_handler(chunks: list[dict[str, object]]) -> _Handler:
    body = "\n".join(json.dumps(c) for c in chunks) + "\n"

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            content=body.encode("utf-8"),
            headers={"content-type": "application/x-ndjson"},
        )

    return handler


async def _collect(stream: AsyncIterator[ChatChunk]) -> list[ChatChunk]:
    return [c async for c in stream]


async def test_stream_chat_yields_chunks_then_done() -> None:
    handler = _ndjson_handler(
        [
            {"message": {"role": "assistant", "content": "hel"}, "done": False},
            {"message": {"role": "assistant", "content": "lo "}, "done": False},
            {"message": {"role": "assistant", "content": "world"}, "done": False},
            {
                "message": {"role": "assistant", "content": ""},
                "done": True,
                "prompt_eval_count": 12,
                "eval_count": 3,
            },
        ],
    )
    client = _make_client(handler)
    try:
        chunks = await _collect(
            client.stream_chat([ChatMessage(role="user", content="hi")]),
        )
    finally:
        await client.aclose()

    assert [c.delta for c in chunks] == ["hel", "lo ", "world", ""]
    assert [c.done for c in chunks] == [False, False, False, True]
    assert chunks[-1].usage is not None
    assert chunks[-1].usage.prompt_tokens == 12
    assert chunks[-1].usage.completion_tokens == 3


async def test_stream_chat_passes_role_to_model_tag() -> None:
    seen: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen.update(json.loads(request.read()))
        return httpx.Response(
            200,
            content=(json.dumps({"done": True}) + "\n").encode("utf-8"),
        )

    client = _make_client(handler)
    try:
        await _collect(
            client.stream_chat(
                [ChatMessage(role="user", content="hi")],
                role=LLMRole.DEEP,
            ),
        )
    finally:
        await client.aclose()

    assert seen["model"] == "deep:14b"
    assert seen["stream"] is True


async def test_stream_chat_skips_blank_lines() -> None:
    body = (
        json.dumps({"message": {"role": "assistant", "content": "a"}, "done": False})
        + "\n\n"
        + json.dumps({"done": True, "prompt_eval_count": 1, "eval_count": 1})
        + "\n"
    )

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=body.encode("utf-8"))

    client = _make_client(handler)
    try:
        chunks = await _collect(
            client.stream_chat([ChatMessage(role="user", content="hi")]),
        )
    finally:
        await client.aclose()
    assert len(chunks) == 2
    assert chunks[0].delta == "a"
    assert chunks[1].done is True


async def test_stream_chat_5xx_raises_ollama_unavailable() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(503, content=b"")

    client = _make_client(handler)
    try:
        with pytest.raises(OllamaUnavailableError):
            await _collect(
                client.stream_chat([ChatMessage(role="user", content="hi")]),
            )
    finally:
        await client.aclose()


async def test_stream_chat_4xx_raises_ollama_response_error() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, content=b"model not found")

    client = _make_client(handler)
    try:
        with pytest.raises(OllamaResponseError):
            await _collect(
                client.stream_chat([ChatMessage(role="user", content="hi")]),
            )
    finally:
        await client.aclose()


async def test_stream_chat_transport_error_raises_ollama_unavailable() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused")

    client = _make_client(handler)
    try:
        with pytest.raises(OllamaUnavailableError):
            await _collect(
                client.stream_chat([ChatMessage(role="user", content="hi")]),
            )
    finally:
        await client.aclose()


async def test_stream_chat_malformed_chunk_raises() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            content=b'{"message":{"role":"assistant","content":"a"},"done":false}\nnot json\n',
        )

    client = _make_client(handler)
    try:
        with pytest.raises(OllamaUnavailableError, match="not valid JSON"):
            await _collect(
                client.stream_chat([ChatMessage(role="user", content="hi")]),
            )
    finally:
        await client.aclose()


async def test_stream_chat_non_object_chunk_raises() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b'["not", "an", "object"]\n')

    client = _make_client(handler)
    try:
        with pytest.raises(OllamaUnavailableError, match="not a JSON object"):
            await _collect(
                client.stream_chat([ChatMessage(role="user", content="hi")]),
            )
    finally:
        await client.aclose()


async def test_stream_chat_tolerates_missing_message_field() -> None:
    """Ollama's terminal chunk often omits message entirely; the client
    yields an empty delta in that case rather than raising."""
    handler = _ndjson_handler(
        [
            {"message": {"role": "assistant", "content": "x"}, "done": False},
            {"done": True, "prompt_eval_count": 0, "eval_count": 0},
        ],
    )
    client = _make_client(handler)
    try:
        chunks = await _collect(
            client.stream_chat([ChatMessage(role="user", content="hi")]),
        )
    finally:
        await client.aclose()
    assert chunks[1].delta == ""
    assert chunks[1].done is True


def test_chat_chunk_is_frozen() -> None:
    from pydantic import ValidationError

    chunk = ChatChunk(delta="hi", done=False)
    with pytest.raises(ValidationError):
        chunk.delta = "other"  # type: ignore[misc]
