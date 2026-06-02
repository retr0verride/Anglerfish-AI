"""Tests for :class:`anglerfish.llm.TokenBudget` (Stage 5 slice 5)."""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncGenerator, Callable
from typing import cast

import httpx
import pytest

from anglerfish.config.models import OllamaConfig
from anglerfish.llm import (
    BudgetExhaustedError,
    ChatChunk,
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
    b = TokenBudget(fast_token_cap=100, deep_token_cap=50, embed_token_cap=200)
    b.consume(LLMRole.FAST, 30)
    snapshot = b.as_dict()
    assert snapshot == {
        "fast": {"cap": 100, "consumed": 30, "remaining": 70},
        "deep": {"cap": 50, "consumed": 0, "remaining": 50},
        "embed": {"cap": 200, "consumed": 0, "remaining": 200},
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


# ---------------------------------------------------------------------------
# Concurrency: shared-budget atomicity (audit M2)
# ---------------------------------------------------------------------------


class _SlowTransport(httpx.AsyncBaseTransport):
    """An async transport that awaits before responding.

    The default MockTransport handler is synchronous, so concurrent
    chat() coroutines never interleave at the network await and the race
    cannot manifest. A real await point forces the interleave.
    """

    def __init__(self, *, prompt_tokens: int, eval_tokens: int) -> None:
        self._prompt = prompt_tokens
        self._eval = eval_tokens

    async def handle_async_request(self, _request: httpx.Request) -> httpx.Response:
        await asyncio.sleep(0.02)
        return httpx.Response(
            200,
            json={
                "message": {"role": "assistant", "content": "ok"},
                "prompt_eval_count": self._prompt,
                "eval_count": self._eval,
                "done": True,
            },
        )


def _slow_client(*, prompt_tokens: int, eval_tokens: int) -> LLMClient:
    http = httpx.AsyncClient(
        transport=_SlowTransport(prompt_tokens=prompt_tokens, eval_tokens=eval_tokens),
        base_url="http://127.0.0.1:11434",
    )
    return LLMClient(OllamaConfig(fast_model="fast:7b"), http_client=http)


async def test_concurrent_same_session_chat_does_not_overshoot_budget() -> None:
    """Concurrent calls sharing one budget must not overshoot the cap (M2).

    Each call consumes 100 tokens; the budget holds exactly one call.
    Without the budget lock all five clear check() before any consume()
    and overshoot to 500. With it, the calls serialise: one fits, the
    rest are refused, and consumed never exceeds the cap.
    """
    import asyncio

    client = _slow_client(prompt_tokens=50, eval_tokens=50)
    budget = TokenBudget(fast_token_cap=100)
    msgs = [ChatMessage(role="user", content="hi")]
    try:
        results = await asyncio.gather(
            *[client.chat(msgs, budget=budget) for _ in range(5)],
            return_exceptions=True,
        )
    finally:
        await client.aclose()

    successes = [r for r in results if not isinstance(r, Exception)]
    exhausted = [r for r in results if isinstance(r, BudgetExhaustedError)]
    assert len(successes) == 1
    assert len(exhausted) == 4
    assert budget.consumed_fast == 100  # exactly the cap, no overshoot


async def test_distinct_budgets_run_concurrently_without_blocking() -> None:
    """Different sessions (distinct budgets) must not serialise on M2's lock."""
    import asyncio

    client = _slow_client(prompt_tokens=1, eval_tokens=1)
    msgs = [ChatMessage(role="user", content="hi")]
    budgets = [TokenBudget(fast_token_cap=100) for _ in range(5)]
    try:
        results = await asyncio.gather(*[client.chat(msgs, budget=b) for b in budgets])
    finally:
        await client.aclose()
    # All five succeed; each distinct budget consumed its own 2 tokens.
    assert len(results) == 5
    assert all(b.consumed_fast == 2 for b in budgets)


async def test_stream_chat_early_break_does_not_hold_budget_lock() -> None:
    """An abandoned stream must not keep the per-session budget lock held
    (audit review R3).

    The previous code held ``budget.lock`` across the stream's ``yield``s,
    so a consumer that broke out early suspended the generator with the
    lock still held; the next command on the same session then deadlocked
    acquiring the same per-session lock.
    """
    ndjson = (
        json.dumps({"message": {"content": "a"}, "done": False})
        + "\n"
        + json.dumps({"message": {"content": "b"}, "done": False})
        + "\n"
        + json.dumps(
            {"message": {"content": "c"}, "done": True, "prompt_eval_count": 1, "eval_count": 1},
        )
        + "\n"
    )

    def handler(_req: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=ndjson.encode("utf-8"))

    client = _make_client(handler)
    budget = TokenBudget(fast_token_cap=100_000)
    # stream_chat is an async generator; cast so .aclose() type-checks
    # (its declared return type is the narrower AsyncIterator).
    gen = cast(
        "AsyncGenerator[ChatChunk, None]",
        client.stream_chat([ChatMessage(role="user", content="hi")], budget=budget),
    )
    try:
        # Take one chunk, then abandon the generator (the realistic
        # early-break case: a `break` out of an `async for`).
        first = await gen.__anext__()
        assert first.delta == "a"

        async def _second() -> list[str]:
            return [
                chunk.delta
                async for chunk in client.stream_chat(
                    [ChatMessage(role="user", content="hi")],
                    budget=budget,
                )
            ]

        # Must not block on the lock the suspended first generator would
        # otherwise be holding.
        deltas = await asyncio.wait_for(_second(), timeout=2.0)
        assert deltas == ["a", "b", "c"]
    finally:
        await gen.aclose()
        await client.aclose()
