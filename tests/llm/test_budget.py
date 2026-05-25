"""Tests for :class:`anglerfish.llm.TokenBudget` (Stage 5 slice 5)."""

from __future__ import annotations

import json
from collections.abc import Callable

import httpx
import pytest

from anglerfish.config.models import OllamaConfig
from anglerfish.llm import (
    BudgetExhaustedError,
    ChatMessage,
    LLMClient,
    LLMRole,
    TokenBudget,
)

_Handler = Callable[[httpx.Request], httpx.Response]


def _make_client(handler: _Handler) -> LLMClient:
    transport = httpx.MockTransport(handler)
    http = httpx.AsyncClient(transport=transport, base_url="http://127.0.0.1:11434")
    return LLMClient(
        OllamaConfig(fast_model="fast:7b", deep_model="deep:14b"),
        http_client=http,
    )


def _ok_handler(prompt_tokens: int = 5, eval_tokens: int = 3) -> _Handler:
    def handler(_req: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "message": {"role": "assistant", "content": "ok"},
                "prompt_eval_count": prompt_tokens,
                "eval_count": eval_tokens,
                "done": True,
            },
        )

    return handler


# ---------------------------------------------------------------------------
# TokenBudget primitive
# ---------------------------------------------------------------------------


def test_token_budget_remaining_starts_at_cap() -> None:
    b = TokenBudget(fast_token_cap=100, deep_token_cap=50)
    assert b.remaining(LLMRole.FAST) == 100
    assert b.remaining(LLMRole.DEEP) == 50


def test_token_budget_consume_decrements_correctly() -> None:
    b = TokenBudget(fast_token_cap=100, deep_token_cap=50)
    b.consume(LLMRole.FAST, 30)
    assert b.remaining(LLMRole.FAST) == 70
    b.consume(LLMRole.FAST, 70)
    assert b.remaining(LLMRole.FAST) == 0
    b.consume(LLMRole.FAST, 5)  # overshoot allowed
    assert b.remaining(LLMRole.FAST) == 0  # clamped


def test_token_budget_check_raises_when_exhausted() -> None:
    b = TokenBudget(fast_token_cap=10, deep_token_cap=20)
    b.consume(LLMRole.FAST, 10)
    with pytest.raises(BudgetExhaustedError, match="fast"):
        b.check(LLMRole.FAST)
    # Deep tier still has budget.
    b.check(LLMRole.DEEP)


def test_token_budget_zero_cap_immediately_exhausted() -> None:
    b = TokenBudget(fast_token_cap=0, deep_token_cap=20)
    with pytest.raises(BudgetExhaustedError):
        b.check(LLMRole.FAST)


def test_token_budget_negative_cap_rejected() -> None:
    with pytest.raises(ValueError, match=">= 0"):
        TokenBudget(fast_token_cap=-1)
    with pytest.raises(ValueError, match=">= 0"):
        TokenBudget(deep_token_cap=-1)


def test_token_budget_consume_negative_rejected() -> None:
    b = TokenBudget()
    with pytest.raises(ValueError, match=">= 0"):
        b.consume(LLMRole.FAST, -1)


def test_token_budget_as_dict_shape() -> None:
    b = TokenBudget(fast_token_cap=100, deep_token_cap=50)
    b.consume(LLMRole.FAST, 30)
    snapshot = b.as_dict()
    assert snapshot == {
        "fast": {"cap": 100, "consumed": 30, "remaining": 70},
        "deep": {"cap": 50, "consumed": 0, "remaining": 50},
    }


# ---------------------------------------------------------------------------
# LLMClient.chat budget integration
# ---------------------------------------------------------------------------


async def test_chat_consumes_budget_on_success() -> None:
    client = _make_client(_ok_handler(prompt_tokens=10, eval_tokens=15))
    budget = TokenBudget(fast_token_cap=100, deep_token_cap=100)
    try:
        await client.chat([ChatMessage(role="user", content="hi")], budget=budget)
    finally:
        await client.aclose()
    assert budget.consumed_fast == 25
    assert budget.consumed_deep == 0


async def test_chat_raises_when_budget_exhausted_before_call() -> None:
    ollama_calls = 0

    def handler(_req: httpx.Request) -> httpx.Response:
        nonlocal ollama_calls
        ollama_calls += 1
        return httpx.Response(200, json={"message": {"content": "ok"}, "done": True})

    client = _make_client(handler)
    budget = TokenBudget(fast_token_cap=0, deep_token_cap=100)
    try:
        with pytest.raises(BudgetExhaustedError):
            await client.chat([ChatMessage(role="user", content="hi")], budget=budget)
    finally:
        await client.aclose()
    assert ollama_calls == 0  # Ollama never reached


async def test_chat_with_no_budget_does_not_track() -> None:
    client = _make_client(_ok_handler(prompt_tokens=10, eval_tokens=5))
    try:
        result = await client.chat([ChatMessage(role="user", content="hi")])
    finally:
        await client.aclose()
    assert result.usage.prompt_tokens == 10  # still parsed
    assert result.usage.completion_tokens == 5


# ---------------------------------------------------------------------------
# LLMClient.stream_chat budget integration
# ---------------------------------------------------------------------------


async def test_stream_chat_consumes_budget_on_terminal_chunk() -> None:
    ndjson = (
        json.dumps({"message": {"content": "a"}, "done": False})
        + "\n"
        + json.dumps(
            {
                "message": {"content": "b"},
                "done": True,
                "prompt_eval_count": 4,
                "eval_count": 6,
            },
        )
        + "\n"
    )

    def handler(_req: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=ndjson.encode("utf-8"))

    client = _make_client(handler)
    budget = TokenBudget(fast_token_cap=100)
    try:
        chunks = [
            c
            async for c in client.stream_chat(
                [ChatMessage(role="user", content="hi")],
                budget=budget,
            )
        ]
    finally:
        await client.aclose()
    assert len(chunks) == 2
    assert budget.consumed_fast == 10


async def test_stream_chat_raises_when_budget_exhausted_before_request() -> None:
    ollama_calls = 0

    def handler(_req: httpx.Request) -> httpx.Response:
        nonlocal ollama_calls
        ollama_calls += 1
        return httpx.Response(200, content=b'{"done":true}\n')

    client = _make_client(handler)
    budget = TokenBudget(fast_token_cap=0)
    try:
        with pytest.raises(BudgetExhaustedError):
            async for _ in client.stream_chat(
                [ChatMessage(role="user", content="hi")],
                budget=budget,
            ):
                pass
    finally:
        await client.aclose()
    assert ollama_calls == 0


async def test_stream_chat_does_not_consume_on_partial_failure() -> None:
    """If the stream errors before the terminal chunk, no budget is consumed."""
    body = b'{"message":{"content":"a"},"done":false}\nnot json\n'

    def handler(_req: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=body)

    from anglerfish.llm.errors import OllamaUnavailableError

    client = _make_client(handler)
    budget = TokenBudget(fast_token_cap=100)
    try:
        with pytest.raises(OllamaUnavailableError):
            async for _ in client.stream_chat(
                [ChatMessage(role="user", content="hi")],
                budget=budget,
            ):
                pass
    finally:
        await client.aclose()
    assert budget.consumed_fast == 0


async def test_chat_deep_role_consumes_deep_bucket() -> None:
    client = _make_client(_ok_handler(prompt_tokens=2, eval_tokens=3))
    budget = TokenBudget(fast_token_cap=100, deep_token_cap=100)
    try:
        await client.chat(
            [ChatMessage(role="user", content="hi")],
            role=LLMRole.DEEP,
            budget=budget,
        )
    finally:
        await client.aclose()
    assert budget.consumed_fast == 0
    assert budget.consumed_deep == 5
