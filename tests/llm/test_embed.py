"""Tests for :meth:`anglerfish.llm.LLMClient.embed` (Stage 8 slice 1)."""

from __future__ import annotations

import json
from collections.abc import Callable

import httpx
import pytest

from anglerfish.config.models import OllamaConfig
from anglerfish.llm import BudgetExhaustedError, LLMClient, LLMRole, TokenBudget
from anglerfish.llm.errors import OllamaResponseError, OllamaUnavailableError

_Handler = Callable[[httpx.Request], httpx.Response]


def _make_client(handler: _Handler) -> LLMClient:
    transport = httpx.MockTransport(handler)
    http = httpx.AsyncClient(transport=transport, base_url="http://127.0.0.1:11434")
    return LLMClient(
        OllamaConfig(
            fast_model="fast:7b",
            deep_model="deep:14b",
            embed_model="nomic-embed-test",
        ),
        http_client=http,
    )


def _ok_handler(vector: list[float]) -> _Handler:
    def handler(_req: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"embedding": vector})

    return handler


# ---------------------------------------------------------------------------
# Routing + happy path
# ---------------------------------------------------------------------------


async def test_embed_returns_vector_as_tuple_of_floats() -> None:
    client = _make_client(_ok_handler([0.1, -0.2, 0.3]))
    try:
        vec = await client.embed("ls /etc")
    finally:
        await client.aclose()
    assert vec == (0.1, -0.2, 0.3)
    assert all(isinstance(x, float) for x in vec)


async def test_embed_passes_embed_model_tag_to_request() -> None:
    seen: list[dict[str, object]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(json.loads(request.read()))
        return httpx.Response(200, json={"embedding": [0.1]})

    client = _make_client(handler)
    try:
        await client.embed("hi")
    finally:
        await client.aclose()
    assert seen[0]["model"] == "nomic-embed-test"
    assert seen[0]["input"] == "hi"


async def test_embed_accepts_batch_shape_with_single_vector() -> None:
    """Ollama may return `embeddings: [[...]]` (newer batch shape)."""
    client = _make_client(
        lambda _r: httpx.Response(200, json={"embeddings": [[1.0, 2.0]]}),
    )
    try:
        vec = await client.embed("x")
    finally:
        await client.aclose()
    assert vec == (1.0, 2.0)


# ---------------------------------------------------------------------------
# Budget integration
# ---------------------------------------------------------------------------


async def test_embed_consumes_estimated_tokens_on_success() -> None:
    client = _make_client(_ok_handler([0.0] * 4))
    budget = TokenBudget(embed_token_cap=1000)
    try:
        # 16 chars // 4 = 4 estimated tokens.
        await client.embed("sixteen-char str", budget=budget)
    finally:
        await client.aclose()
    assert budget.consumed_embed == 4


async def test_embed_charges_at_least_one_token_for_short_input() -> None:
    client = _make_client(_ok_handler([0.0]))
    budget = TokenBudget(embed_token_cap=10)
    try:
        await client.embed("x", budget=budget)
    finally:
        await client.aclose()
    assert budget.consumed_embed == 1


async def test_embed_raises_when_budget_exhausted_before_request() -> None:
    calls = 0

    def handler(_req: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(200, json={"embedding": [0.1]})

    client = _make_client(handler)
    budget = TokenBudget(embed_token_cap=0)
    try:
        with pytest.raises(BudgetExhaustedError):
            await client.embed("hello", budget=budget)
    finally:
        await client.aclose()
    assert calls == 0


async def test_embed_does_not_consume_fast_or_deep_budgets() -> None:
    client = _make_client(_ok_handler([0.0]))
    budget = TokenBudget(fast_token_cap=10, deep_token_cap=10, embed_token_cap=100)
    try:
        await client.embed("payload payload payload", budget=budget)
    finally:
        await client.aclose()
    assert budget.consumed_fast == 0
    assert budget.consumed_deep == 0
    assert budget.consumed_embed > 0


# ---------------------------------------------------------------------------
# Error mapping
# ---------------------------------------------------------------------------


async def test_embed_5xx_raises_ollama_unavailable() -> None:
    client = _make_client(lambda _r: httpx.Response(503, text="overloaded"))
    try:
        with pytest.raises(OllamaUnavailableError):
            await client.embed("x")
    finally:
        await client.aclose()


async def test_embed_4xx_raises_ollama_response_error() -> None:
    client = _make_client(lambda _r: httpx.Response(404, text="not found"))
    try:
        with pytest.raises(OllamaResponseError):
            await client.embed("x")
    finally:
        await client.aclose()


async def test_embed_transport_error_raises_ollama_unavailable() -> None:
    def handler(_r: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused")

    client = _make_client(handler)
    try:
        with pytest.raises(OllamaUnavailableError):
            await client.embed("x")
    finally:
        await client.aclose()


async def test_embed_missing_vector_field_raises() -> None:
    client = _make_client(lambda _r: httpx.Response(200, json={}))
    try:
        with pytest.raises(OllamaResponseError, match="missing 'embedding'"):
            await client.embed("x")
    finally:
        await client.aclose()


async def test_embed_non_numeric_element_raises() -> None:
    client = _make_client(
        lambda _r: httpx.Response(200, json={"embedding": [0.1, "oops"]}),
    )
    try:
        with pytest.raises(OllamaResponseError, match="non-numeric"):
            await client.embed("x")
    finally:
        await client.aclose()


# ---------------------------------------------------------------------------
# Warm dispatch for EMBED role
# ---------------------------------------------------------------------------


async def test_warm_for_embed_role_uses_embeddings_endpoint() -> None:
    seen_paths: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen_paths.append(request.url.path)
        return httpx.Response(200, json={"embedding": []})

    client = _make_client(handler)
    try:
        await client.warm(LLMRole.EMBED)
    finally:
        await client.aclose()
    assert seen_paths == ["/api/embeddings"]


async def test_warm_for_chat_roles_still_uses_generate() -> None:
    seen_paths: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen_paths.append(request.url.path)
        return httpx.Response(200, json={"done": True})

    client = _make_client(handler)
    try:
        await client.warm(LLMRole.FAST)
        await client.warm(LLMRole.DEEP)
    finally:
        await client.aclose()
    assert seen_paths == ["/api/generate", "/api/generate"]


# ---------------------------------------------------------------------------
# model_for + role enum coverage
# ---------------------------------------------------------------------------


def test_model_for_embed_returns_embed_model_tag() -> None:
    client = LLMClient(OllamaConfig(embed_model="nomic-embed-test"))
    assert client.model_for(LLMRole.EMBED) == "nomic-embed-test"


def test_llm_role_embed_is_a_member() -> None:
    assert LLMRole.EMBED.value == "embed"
